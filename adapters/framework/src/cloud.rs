//! A cloud the harness can steer.
//!
//! Lives on the unprivileged side, which is the point: the privileged helper
//! reaches it only through the socket, so anything the harness makes it do is
//! also something a compromised sync daemon could do.

use hydration_client::upload::{Sink, Uploaded};
use hydration_client::Provider;
use hydration_conformance::{CloudObject, CloudOp, FetchBehaviour};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Condvar, Mutex};

#[derive(Default)]
pub struct State {
    pub objects: HashMap<String, CloudObject>,
    pub ops: Vec<CloudOp>,
    pub next_id: u32,
    pub fetch: HashMap<String, FetchBehaviour>,
    /// Uploads are let in but not let out, so a rename or unlink can be made to
    /// land strictly inside the window.
    pub holding: bool,
    /// Set the moment an upload enters, so the harness can wait for the race to
    /// be arranged rather than sleeping and hoping.
    pub upload_entered: bool,
}

#[derive(Clone, Default)]
pub struct Cloud {
    pub state: Arc<Mutex<State>>,
    pub gate: Arc<Condvar>,
}

impl Cloud {
    pub fn seed(&self, name: &str, content: &[u8], etag: &str) -> String {
        let mut st = self.state.lock().unwrap();
        st.next_id += 1;
        let id = format!("cloud-{}", st.next_id);
        st.objects.insert(
            id.clone(),
            CloudObject {
                id: id.clone(),
                name: name.to_string(),
                content: content.to_vec(),
                etag: etag.to_string(),
            },
        );
        id
    }

    /// The newest object with this name.
    ///
    /// "Newest" rather than "the one we happen to find" because a rename over a
    /// placeholder legitimately produces two: the renamed file is the ex-temp
    /// inode, which carries no cloud id, so its upload creates a fresh object
    /// while the seeded one is orphaned under the same name. `HashMap` iteration
    /// order is randomised per process, so `find` returned either of them and
    /// 5.4 failed on roughly a coin toss with "the cloud holds stale content".
    ///
    /// Picking the newest makes the harness deterministic. It does not answer
    /// the design question underneath, which is real and belongs in §5.4: after
    /// `write temp -> rename over target`, *which* cloud object is the target?
    /// The framework currently orphans the original instead of either updating
    /// it or deleting it, and neither the contract nor the code says which it
    /// should be.
    pub fn by_name(&self, name: &str) -> Option<CloudObject> {
        let st = self.state.lock().unwrap();
        let mut hits: Vec<&CloudObject> = st.objects.values().filter(|o| o.name == name).collect();
        hits.sort_by_key(|o| {
            o.id.rsplit('-')
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(0)
        });
        hits.last().map(|o| (*o).clone())
    }

    pub fn ops(&self) -> Vec<CloudOp> {
        self.state.lock().unwrap().ops.clone()
    }

    pub fn hold(&self) {
        let mut st = self.state.lock().unwrap();
        st.holding = true;
        st.upload_entered = false;
    }

    pub fn release(&self) {
        let mut st = self.state.lock().unwrap();
        st.holding = false;
        self.gate.notify_all();
        drop(st);
    }

    pub fn upload_started(&self) -> bool {
        self.state.lock().unwrap().upload_entered
    }

    pub fn set_behaviour(&self, name: &str, b: FetchBehaviour) {
        self.state.lock().unwrap().fetch.insert(name.to_string(), b);
    }
}

impl Provider for Cloud {
    fn fetch(
        &mut self,
        cloud_id: &str,
        size: u64,
        _content_tag: Option<&str>,
        span: hydration_protocol::Span,
        out: &mut hydration_protocol::transport::Body<'_>,
    ) -> io::Result<()> {
        use std::io::Write;
        let mut st = self.state.lock().unwrap();
        st.ops.push(CloudOp::Get {
            id: cloud_id.to_string(),
        });
        let Some(obj) = st.objects.get(cloud_id).cloned() else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no such object"));
        };
        let bytes = match st.fetch.get(&obj.name) {
            // Short on purpose: the suite's 5.7 case. `Body` refuses to call it
            // finished, so this becomes an abort rather than a truncated file.
            //
            // Shortened against the *span*, because that is what this transfer
            // promised. Truncating the object instead would deliver the whole
            // span for any range that ends before the cut, and the case would
            // stop testing anything.
            Some(FetchBehaviour::Short { bytes }) => {
                let want = (*bytes as u64).min(span.len) as usize;
                vec![b'x'; want]
            }
            Some(FetchBehaviour::Stale { .. }) => vec![b'!'; span.len as usize],
            // The ordinary path: the slice of the object that was asked for.
            _ => {
                let end = (span.end() as usize).min(obj.content.len());
                let start = (span.offset as usize).min(end);
                obj.content[start..end].to_vec()
            }
        };
        let _ = size;
        drop(st);
        out.write_all(&bytes)?;
        Ok(())
    }
}

impl Sink for Cloud {
    fn upload(&mut self, path: &std::path::Path, existing: Option<&str>) -> io::Result<Uploaded> {
        // The name is read here, at send time — never captured when the job was
        // queued. That is rule 2, and this is the line where an atomic save
        // either works or does not.
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let content = std::fs::read(path)?;

        let mut st = self.state.lock().unwrap();
        st.upload_entered = true;
        self.gate.notify_all();
        // In flight from here until the harness lets go.
        while st.holding {
            st = self.gate.wait(st).unwrap();
        }

        st.ops.push(CloudOp::Put {
            name: name.clone(),
            content: content.clone(),
        });
        let id = match existing {
            Some(e) if st.objects.contains_key(e) => e.to_string(),
            _ => {
                st.next_id += 1;
                format!("cloud-{}", st.next_id)
            }
        };
        let etag = format!("etag-{}", st.next_id);
        st.objects.insert(
            id.clone(),
            CloudObject {
                id: id.clone(),
                name,
                content,
                etag: etag.clone(),
            },
        );
        Ok(Uploaded {
            cloud_id: id,
            etag: Some(etag),
        })
    }

    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        let mut st = self.state.lock().unwrap();
        st.ops.push(CloudOp::Delete {
            id: cloud_id.to_string(),
        });
        st.objects.remove(cloud_id);
        Ok(())
    }
}
