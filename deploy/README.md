# Deployment

Three units and one mount, arranged so that the failure nothing inside the
process can cover — both halves of the helper dying at once — takes the files
out of reach instead of turning them into zeros.

## Why the sync folder needs its own volume

Measured, in `probes/dirmark.c` and the bind-mount runs recorded in DESIGN.md
§6.4a:

* A **directory mark is accepted and delivers nothing.** `fanotify_mark` returns
  0 and every dehydrated file reads back as zeros. Only mount and filesystem
  marks work.
* `FAN_MARK_FILESYSTEM` on `/home` would put **every file access in the user's
  home** through a blocking handler. Not an option.
* A **bind mount is not enough.** Binding to a separate path leaves the original
  reachable; binding over itself is bypassed by a non-recursive bind of the
  *parent*, which is what container runtimes and `systemd`'s own `BindPaths=`
  do routinely.

So: a real, separate mount. On a typical Arch/CachyOS layout a btrfs subvolume
is the cheap way to get one — the btrfs root (`subvolid=5`) is not mounted, so
`@onedrive` mounted at `~/OneDrive` has no other path to it.

```bash
sudo btrfs subvolume create /mnt/@onedrive   # with subvolid=5 mounted at /mnt
```

The requirement is stricter than "its own mount", and it is worth stating in the
form that is actually true:

> No other mount in the system may expose the sync files.

That is a property of the whole machine's mount table, not of our setup, and
**we cannot enforce it** — anyone can create a bypass afterwards. `hydrationd`
watches for it with `FAN_MNT_ATTACH` and reports it, because a hazard we cannot
prevent is one that must not be silent.

## The units

| Unit | Runs as | Holds |
|---|---|---|
| `hydration-mount.mount` | system | the sync volume |
| `hydrationd.service` | **root**, `CAP_SYS_ADMIN` only | the fanotify group |
| `hydration-sync.service` | the user | the credentials |

The ordering is the point. `hydrationd.service` is `BindsTo=` the mount and
`StopPropagatedFrom=` it, so the two live and die together: if the helper stops
for any reason — including both its processes being killed — the mount goes with
it, and the files become *unreachable* rather than readable-as-zeros.

`hydration-sync.service` may come and go freely. Losing it means hydration fails
with `EIO`, which is a correct answer.

## Not runnable yet

`hydrationd` and `hydration-sync` are libraries. There is no `main` for either,
so the `ExecStart=` lines above point at binaries that do not exist and
`systemd-analyze verify` says so.

The units are here anyway, because the part of them that matters is not the
command line — it is the `BindsTo=`/`StopPropagatedFrom=` pair, which is the
only answer to a failure the code cannot handle. That belongs in the repository
next to the reasoning, not in someone's notes until the binaries land.

## Installing

```bash
sudo cp deploy/hydrationd.service deploy/hydration-mount.mount /etc/systemd/system/
mkdir -p ~/.config/systemd/user
cp deploy/hydration-sync.service ~/.config/systemd/user/
sudo systemctl daemon-reload && systemctl --user daemon-reload
sudo systemctl enable --now hydrationd.service
systemctl --user enable --now hydration-sync.service
```

## Checking it is actually safe

The property to verify is not "it starts". It is that killing the helper takes
the mount with it:

```bash
sudo systemctl kill --signal=SIGKILL --kill-whom=all hydrationd.service
mountpoint -q ~/OneDrive && echo "STILL MOUNTED — files can be read as zeros" \
                         || echo "unmounted, as it should be"
```
