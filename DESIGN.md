# Hydrerings-API for skyfiler på Linux — designdokument

**Status:** Fase 1, beslutningsgrunnlag. Ingen implementasjon.
**Verifisert mot:** Linux 7.1.6 (CachyOS), btrfs, FUSE-protokoll 7.45, libfuse 3.18.2.
**Referanseklient:** `github.com/franzjeger/OneDriveForLinux` @ `f1f090c` (Rust, FUSE, 2 241 linjer i `crates/vfs`).

---

## 1. Anbefaling

**Ikke skriv kjernekode. Ikke bygg videre på FUSE heller.**

Bygg rammeverket på **fanotify pre-content-hendelser** (`FAN_CLASS_PRE_CONTENT` +
`FAN_PRE_ACCESS`) over et *ekte* lokalt filsystem — ext4, btrfs eller xfs. Filene
ligger som vanlige, sparsomme filer i hjemmeområdet. Kjernen eier POSIX-kontrakten.
Rammeverket eier bare to ting: å fylle innhold ved første tilgang, og å sende
endringer oppover.

Dette er Linux' faktiske ekvivalent til Windows' Cloud Files API. Det er en
filterrolle over et ekte filsystem, ikke et filsystem — akkurat som CFAPI er en
filterdriver over NTFS, ikke en NTFS-erstatning. Mekanismen finnes i kjernen i dag,
den er i produksjon hos Meta for HSM, og jeg har verifisert at den virker på denne
maskinen.

Prisen er tre ting, og alle tre er obligatoriske i v1 — ikke pynt som kan skyves:

1. **`CAP_SYS_ADMIN`**, som FUSE-passthrough også krever. Den prisen betaler du uansett
   hvis du vil ha native ytelse. Den må håndteres med privilegieseparasjon (§6b).
2. **Naken fanotify feiler åpent** — en dehydrert fil leser som stille nuller hvis
   daemonen dør. Det er verre enn FUSE. Løsbart, målt, men bare med super/worker-mønsteret
   i §6a.
3. **Ingen «ikke hydrer»-hint i APIet.** Windows og macOS har det; Linux har det ikke.
   Masselesing må håndteres med en policy vi designer selv (§6c), og den policyen er en
   produktdel, ikke en implementasjonsdetalj.

Uten alle tre er dette ikke bedre enn det du har. Med dem er det vesentlig bedre.

**Det avgjørende argumentet:** alle seks buggene du fikset denne uken sitter i
metadata-, identitets- og navnestier — ikke i lesing av bytes. FUSE med passthrough
fjerner I/O-kostnaden, men lar deg beholde *hele* korrekthetsbyrden. Du betaler
`CAP_SYS_ADMIN` og sitter fortsatt igjen med alle seks bugklassene. Med fanotify
forsvinner fire av dem ved konstruksjon, fordi ext4/btrfs/xfs allerede implementerer
dem riktig.

---

## 2. Hva finnes i kjernen i dag

Alt under er verifisert mot kilde eller målt på denne maskinen. Jeg skiller eksplisitt
mellom de to.

### 2.1 `fs/netfs` — ikke tilgjengelig for oss

netfslib er et **rent kjerne-internt API**. Det kan bare brukes av filsystem-moduler i
kjernen. Det er ikke eksponert mot userspace i noen form.

Det gjør mye av det vi vil ha — delrekvisisjoner, sparsom henting, retry, samordning
med sideminne, og skriving mot flere destinasjoner samtidig. Men for å nå det må du
skrive et kjernefilsystem. Det er den dyre veien, og den vurderes i §6.

**Konklusjon:** relevant kun hvis vi skriver kjernekode. Gir ingenting til userspace.

### 2.2 `fscache` / `cachefiles` on-demand — feil form, og bare lesing

`CONFIG_CACHEFILES_ONDEMAND=y` på denne maskinen. Mekanismen finnes og er ekte: en
userspace-daemon poller `/dev/cachefiles` og svarer på forespørsler.

To ting diskvalifiserer den:

1. **Bare tre opkoder: `OPEN`, `CLOSE`, `READ`.** Det finnes ingen write-/writeback-vei.
   Den er bygget for containerimages (erofs over fscache) — les-bare, uforanderlig
   innhold. En skyklient må laste opp.
2. **Den drives av et kjernefilsystem.** cachefiles er en *cache under* en netfs-klient
   (AFS, NFS, Ceph, 9p, erofs). Det er ikke noe man monterer selv. Uten et
   kjernefilsystem over seg har den ingen som stiller forespørslene.

Så «placeholder → hent ved tilgang» er riktignok i praksis samme problem — men denne
implementasjonen av det er låst til lesing og til kjernefilsystemer.

**Konklusjon:** ikke brukbar. Løser halve problemet, i en form vi ikke når.

### 2.3 `FUSE_PASSTHROUGH` — virker, men krever root, og løser feil problem

FUSE-protokoll 7.45 på denne maskinen. Passthrough kom i 7.40 (kjerne 6.9).
Mekanismen: daemonen registrerer en backing-fil med `FUSE_DEV_IOC_BACKING_OPEN`, får en
`backing_id`, og returnerer den i `fuse_open_out` sammen med `FOPEN_PASSTHROUGH`.

Jeg skrev en minimal passthrough-daemon og målte den. Resultater:

| Vei | Gjennomstrømning (256 MB, tmpfs) |
|---|---|
| Direkte lesing av backing-fil (baseline) | 21,9 / 24,3 / 22,0 GB/s |
| Gjennom FUSE **med** passthrough | 20,6 / 20,0 / 21,6 GB/s |
| Gjennom FUSE **uten** passthrough (daemon-servert) | 10,2 / 9,3 / 10,5 GB/s |

Passthrough er altså ~2× raskere enn daemon-servert I/O og lander innenfor ~8 % av
native. Leseren fikk korrekt SHA-256 over 256 MB mens daemonens `read`-handler
returnerte `EIO` på alle kall — kjernen gikk aldri innom userspace. Mekanismen er ekte
og den er god.

**Men den krever `CAP_SYS_ADMIN`.** Fra `fs/fuse/backing.c`:

```c
/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
res = -EPERM;
if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
	goto out;
```

Målt: som uprivilegert bruker feiler `FUSE_DEV_IOC_BACKING_OPEN` med `EPERM` selv om
`FUSE_PASSTHROUGH` ble forhandlet frem i INIT. Som root returnerer den en gyldig
`backing_id`. Merk at det er `capable()`, ikke `ns_capable()` — et user namespace
hjelper ikke.

To feller verdt å kjenne til hvis vi likevel går denne veien:

- **Kun fire FOPEN-flagg kan følge passthrough:** `FOPEN_PASSTHROUGH`,
  `FOPEN_DIRECT_IO`, `FOPEN_PARALLEL_DIRECT_WRITES`, `FOPEN_NOFLUSH`. Setter du noe
  annet — for eksempel `keep_cache` — feiler `open(2)` med **`EIO` og ingen
  diagnostikk**. Kjernekommentaren kaller `FOPEN_KEEP_CACHE` «a strange and undesired
  combination». Jeg gikk i denne fella under målingen; det tok en kildelesing å finne.
- **Passthrough besluttes ved `open`, per åpning.** Du må vite om filen er hydrert i det
  `FUSE_OPEN` behandles. Én `backing_id` per inode.

**Konklusjon:** teknisk god, men den løser bare I/O-kostnaden. Den rører ikke
`getattr`, `rename`, `unlink`, identitet eller `fsync` — som er der alle buggene dine
var. Og den koster like mye privilegium som alternativet i §2.4.

### 2.4 fanotify pre-content — dette er hydrerings-APIet

Dette sto ikke på lista di, og det er funnet i denne undersøkelsen.

`FAN_CLASS_PRE_CONTENT` + `FAN_PRE_ACCESS` er en blokkerende tillatelseshendelse som
fyres **før** innholdet i en fil leses. Den ble laget for nøyaktig dette formålet —
hierarkisk lagringsstyring som fyller filinnhold ved første tilgang — av Amir Goldstein
og Josef Bacik, og er i produksjon hos Meta.

Verifisert på denne maskinen, på btrfs:

```
[hsm] fanotify_init(FAN_CLASS_PRE_CONTENT) OK
[hsm] marked mount hsm for FAN_PRE_ACCESS
[hsm] FAN_PRE_ACCESS pid=573286 fd=4 range=offset=0 count=262144
[hsm] hydrated 36 bytes -> OK
```

Forløpet: en sparsom fil med `size=36 blocks=0` som leste tilbake bare nuller. Med
daemonen kjørende ga `cat` det ekte innholdet, og filen gikk til `blocks=8`. Leseren
merket ingenting. Det er hydrering, på en ekte btrfs-fil, uten et eneste FUSE-lag.

Egenskaper, fra kilde og fra måling:

- **Dekker mer enn lesing.** `fsnotify_file_area_perm()` fyrer på
  `MAY_READ | MAY_WRITE | MAY_ACCESS`. I tillegg finnes `fsnotify_mmap_perm()` for
  `mmap` og `fsnotify_truncate_perm()` for `truncate`. En delvis skriving inn i en
  dehydrert fil utløser altså hydrering først — hullet fylles før skrivingen lander.
  (Det finnes ingen egen `FAN_PRE_MODIFY` i denne kjernen; skriving går gjennom
  `FAN_PRE_ACCESS`.)
- **Byte-område følger med.** `FAN_EVENT_INFO_TYPE_RANGE` gir `offset` og `count`.
  Merk fra målingen: `count` var 262 144 for en `cat` av en 36-bytes fil — det er
  *readahead-vinduet*, ikke syscall-størrelsen, og det kom to overlappende hendelser.
  Hydreringen må være idempotent og tåle overlapp.
- **Filsystemstøtte er bred.** Superblokken må sette `SB_I_ALLOW_HSM`. Verifisert
  ubetinget satt i **btrfs**, **ext4** og **xfs**. Ikke satt i tmpfs/shmem, bcachefs
  eller gfs2. De tre som teller for et hjemmeområde er dekket.
- **Feil kan rapporteres presist.** `FAN_DENY_ERRNO(EIO)` lar deg gi leseren en ekte
  feil når nedlastingen mislykkes, i stedet for stille nuller.
- **Hydrerte filer koster null. Målt.** `FAN_MARK_IGNORE_SURV` fjerner hendelser for en
  fil som allerede er full. `probes/ignoremark.c` bekrefter alle tre leddene: merket
  godtas ved siden av mount-merket, neste lesing gir null hendelser, og undertrykkelsen
  overlever at filen endres — det siste er det `SURV` betyr, og uten det ville en hydrert
  fil som skrives stille begynt å generere hydreringshendelser igjen. Etter hydrering er
  filen en helt vanlig btrfs-fil: ingen daemon i datastien, native ytelse, ikke engang de
  8 % passthrough koster.

**Krever `CAP_SYS_ADMIN`** — målt: `fanotify_init(FAN_CLASS_PRE_CONTENT)` gir `EPERM`
som uprivilegert bruker. Samme pris som passthrough.

---

## 3. Hvorfor FUSE er feil utgangspunkt

De seks invariantene dine er ikke I/O-problemer. De er POSIX-kontraktsproblemer. Et
FUSE-filsystem må implementere hele den kontrakten selv, i userspace, med
nettverkslatens og en database i veien. Det er derfor hver Linux-klient som prøver får
den subtilt feil — ikke fordi utviklerne er uforsiktige, men fordi oppgaven er å
reimplementere noe ext4 har brukt tjue år på å få riktig.

Referanseklienten er et rent eksempel. `crates/vfs/src/filesystem.rs` implementerer
`lookup`, `getattr`, `setattr`, `readdir`, `readdirplus`, `open`, `read`, `write`,
`release`, `mkdir`, `unlink`, `rename`, `getxattr`, `create`, `statfs`, `readlink`.

Den implementerer **ikke** `fsync`. Heller ikke `flush`, `fallocate`, `rmdir`,
`fsyncdir`, `lseek` (`SEEK_HOLE`/`SEEK_DATA`) eller `copy_file_range`. Det er ikke en
forglemmelse man ser ved kodelesing — `fuse3` svarer `ENOSYS`, kjernen husker det og
slutter å sende `FSYNC`, og hver eneste `fsync()` returnerer suksess uten at noe er
gjort. Det er nøyaktig invariant 6, og den er brutt i utgangspunktet, ikke ved en
feiltakelse i en kanttilfelle.

Legg dette ved siden av hva som skjer på et ekte filsystem:

| Invariant | På FUSE | På ekte fs med fanotify |
|---|---|---|
| Størrelse/mtime ved usendte endringer | Du svarer `getattr` fra en database som henger etter opplastingen. Bug #50: `stat` ga 0 byte, filen leste tomt, `fsync` løy. | `stat(2)` leser inoden. Den lokale kopien *er* filen. Riktig ved konstruksjon. |
| POSIX-modus, exec-bit | Du må lagre og gjenskape modus selv. Referanseklienten tar imot `setattr` og forkaster den stille. | Ekte inode, ekte modusbiter. `chmod +x` virker fordi det er `chmod`. |
| Atomisk lagring (`rename` over mål) | Bug #52: opplastingen startet under temp-navnet og vant. Filen forsvant og temp-navnet holdt innholdet. | `rename(2)` er atomisk i kjernen. Det finnes ikke noe vindu å tape. |
| `fsync` | Ikke implementert. Returnerer suksess for data som ikke er varig noe sted. | `fsync(2)` på btrfs. Ekte holdbarhet, ekte feilkode. |
| Filens identitet | Bug #50 og #53: `_local_*` → ekte OneDrive-ID. Tre datataps-bugger, deretter tre kappløp til mellom lesing og ID-bytte. | Inoden er stabil fra fødselen. Sky-ID-en er en kolonne i en sidetabell. **Det finnes ikke noe identitetsbytte.** |
| Sletting under opplasting | Bug #51: opplastingen fullførte, fant ingen rad, gjenopprettet filen fra sin egen foreldede kopi. | Fortsatt vårt ansvar — men uten samtidig ID-bytte er det ett kappløp, ikke tre. |

Fire av seks forsvinner fordi vi slutter å late som vi er et filsystem. De to som blir
igjen — identitet og sletting-under-opplasting — er ekte distribuerte
systemproblemer som ikke har en kjerneløsning uansett arkitektur. De hører hjemme i
rammeverket, og §5 spesifiserer dem.

Til sammenligning: `--vfs-cache-mode full` i rclone bruker sparsomme filer som
range-cache internt, men presenterer fortsatt alt gjennom FUSE — den reimplementerer
kontrakten på samme måte. JuiceFS gjør sin egen POSIX-implementasjon over et
objektlager med en egen metadatamotor. gocryptfs er et krypteringsoverlegg, ikke
on-demand. Ingen av dem gjør CFAPI-modellen. Det er ikke fordi den er dårlig — det er
fordi mekanismen ikke fantes på Linux før nå.

---

## 4. Anbefalt arkitektur

```
┌────────────────────────────────────────────────────────────┐
│ Brukerens filer: ~/OneDrive på ekte ext4/btrfs/xfs          │
│ Dehydrert fil = sparsom fil, riktig størrelse, 0 blokker    │
│ Sky-ID og tilstand i xattr (user.hydration.*)               │
└────────────────────────────────────────────────────────────┘
        │ FAN_PRE_ACCESS (blokkerende)      │ FAN_MODIFY / FAN_CLOSE_WRITE
        ▼                                    ▼
┌──────────────────────────┐        ┌──────────────────────────────┐
│ hydrated (privilegert)   │        │ Endringsdetektor             │
│ ~1–2k linjer, root       │        │ (uprivilegert)               │
│ Eier fanotify-fd-en.     │        └──────────────────────────────┘
│ Gjør INGENTING annet:    │                    │
│ ingen HTTP, ingen auth,  │◄── D-Bus/UNIX ────►│
│ ingen skylogikk.         │    (smal, typet)   │
└──────────────────────────┘                    ▼
                                   ┌──────────────────────────────┐
                                   │ Klientdaemon (uprivilegert)  │
                                   │ Auth, Graph/S3/…, opplasting │
                                   │ Implementerer Provider-APIet │
                                   └──────────────────────────────┘
```

**Todeling er poenget.** Den privilegerte delen er liten nok til å revideres på en
ettermiddag: den holder fanotify-deskriptoren, oversetter en hendelse til en
forespørsel, tar imot bytes over en socket, skriver dem i filen og svarer `FAN_ALLOW`.
Den snakker aldri med nettverket. All skylogikk — OAuth, tokens, delta-sync,
konfliktoppløsning — kjører som brukeren, uten spesielle rettigheter. Presedensen er
`fusermount3`, som er setuid root på denne maskinen av nøyaktig samme grunn.

**Klienten implementerer et smalt grensesnitt.** Skissert, ikke endelig:

```rust
trait CloudProvider {
    /// Hent [offset, offset+len) for denne fila. Kalles med hydreringen ventende.
    async fn fetch_range(&self, id: &CloudId, offset: u64, len: u64) -> Result<Bytes>;
    /// Last opp innholdet. Returnerer ID-en skyen ga den.
    async fn upload(&self, path: &Path, expect: Option<&CloudId>) -> Result<CloudId>;
    async fn remove(&self, id: &CloudId) -> Result<()>;
    async fn list_changes(&self, cursor: &Cursor) -> Result<(Vec<Change>, Cursor)>;
}
```

Alt annet — når det hydreres, hva som er sant om størrelse, hvem som vinner en
sletting — er rammeverkets ansvar og skal ikke være mulig for klienten å få feil.

---

## 5. Kontrakten

Dette er produktet. Hver invariant: hvem eier den, hva garanterer rammeverket, og
hvilken test gjør bruggen umulig.

### 5.1 Filens identitet

**Rammeverket eier den. Klienten ser den aldri bytte.**

Den lokale inoden er identiteten, fra `create(2)` og livet ut. Sky-ID-en er et
*attributt* på den, lagret i `user.hydration.id`, som starter tomt.

Dette er den strukturelle gevinsten ved å ligge på et ekte filsystem: i
referanseklienten *måtte* identiteten byttes, fordi raden var nøkkel og `local_path`
var unik, så `_local_*` og den ekte ID-en aldri kunne eksistere samtidig. Derav
tre datataps-bugger og senere tre kappløp mellom lesing og adopsjon. Her finnes ikke
byttet: `upload()` returnerer en `CloudId`, rammeverket skriver den inn i en xattr på
en fil som har hatt samme inode hele tiden. Ingen rad flyttes. Ingen leser kan se en
mellomtilstand, fordi det ikke finnes noen.

*Garanti:* en fil opprettet lokalt har stabil `st_ino` fra `create` til `unlink`,
uavhengig av opplastingens tilstand.
*Test:* opprett fil, `stat` den, last opp, `stat` igjen — samme inode; les den
kontinuerlig i en tråd gjennom hele opplastingen uten et eneste feilslag.

### 5.2 Størrelse og mtime for en fil med usendte endringer

**Kjernen eier den. Rammeverket har ingen mening.**

Sannheten er den lokale kopien fordi den lokale kopien *er* filen. `stat(2)` går rett
i inoden. Rammeverket svarer aldri på et `getattr`, fordi det aldri blir spurt.

Det ene rammeverket må passe på: en **dehydrert** fil skal ha riktig størrelse med null
allokerte blokker. Det er `truncate(2)` til riktig lengde — verifisert i §2.4:
`size=36 blocks=0`. Serverens metadata skrives til størrelsen *bare* når filen er ren.
Så snart det finnes usendte endringer, rører ingen sync-vei størrelse eller mtime.

*Garanti:* `stat` reflekterer alltid siste lokale skriving, umiddelbart, uansett
opplastingstilstand.
*Test:* skriv 23 byte, `stat` med én gang — `st_size == 23`. (Referanseklientens bug
ga her `left: 0, right: 23`.)

**Merk:** dette gjelder en fil med *lokale* endringer. Tilfellet der placeholderens
størrelse er feil fordi filen endret seg i skyen før noen leste den, er en egen invariant
— se §5.7.

### 5.3 POSIX-modus

**Kjernen eier den. Rammeverket lagrer den som skygge.**

`chmod +x` er et ekte `chmod` på en ekte inode. Exec-biten virker fordi den er exec-
biten. Skyen lagrer den ikke, så rammeverket speiler modus i `user.hydration.mode` slik
at den overlever en dehydrering/rehydrering-runde og kan gjenskapes på en ny maskin.

Merk at dette er *strengt bedre* enn CFAPI, som må gjøre samme jobb mot NTFS-ACL-er.

*Garanti:* modus overlever dehydrering, rehydrering og full ny-synkronisering.
*Test:* `chmod +x`, dehydrer, rehydrer, `test -x` — og kjør programmet.

### 5.4 Atomisk lagring

**Kjernen eier `rename`. Rammeverket eier at ingen opplasting kan referere et navn.**

`write temp → rename over target` er normalen. På et ekte filsystem er `rename(2)`
atomisk og rammeverket kan ikke ødelegge det.

Den gjenværende faren er den referanseklienten gikk på i bug #52: en opplasting som
*startet* under temp-navnet og landet der. Løsningen er en regel, ikke en reparasjon:

> **En opplasting adresseres aldri ved navn. Den adresseres ved inode, og navnet slås
> opp i det øyeblikket forespørselen bygges.**

Det er derfor `upload()` i grensesnittet tar `&Path` som slås opp sent, ikke et navn
som ble fanget da jobben ble køet. Kombinert med at ingen opplasting starter før filen
har vært stille (§5.6), er tilfellet borte ved konstruksjon: når opplastingen starter,
*er* temp-filen blitt den ekte.

*Garanti:* ingen opplasting kan lykkes under et navn filen ikke har når byte-ene sendes.
*Test:* atomisk lagring med opplastingen holdt åpen slik at `rename` lander midt i —
målfilen finnes med riktig innhold, temp-navnet er borte, og ingen av delene reverserer.

### 5.5 Sletting under opplasting

**Rammeverket eier den. Slettingen vinner alltid.**

Slettingen er den nyere intensjonen. Regelen:

> **Fravær av lokal fil er en positiv beskjed, ikke manglende data.** En opplasting som
> fullfører og finner filen borte skal slette det den nettopp lastet opp — aldri
> gjenopprette fra sin egen kopi i minnet.

Referanseklientens bug #51 var nøyaktig `.unwrap_or(item)`: den behandlet «raden er
borte» som «jeg mangler informasjon» og falt tilbake på foreldede data. Rammeverket
skal ikke gi klienten muligheten til å ta det valget — derfor returnerer `upload()` bare
en ID, og rammeverket, ikke klienten, bestemmer hva som skjer med den.

*Garanti:* når `unlink` har returnert, finnes filen ikke i skyen etterpå — heller ikke
hvis opplastingen var i lufta og lyktes.
*Test:* opprett, skriv, lukk, slett inne i opplastingsvinduet (med PUT holdt åpen slik
at kappløpet er deterministisk) — `DELETE` nådde skyen, ingenting kom tilbake.

### 5.6 `fsync`

**Kjernen eier den — men bare hvis vi ikke lyver om den.**

`fsync(2)` på en ekte fil er ekte holdbarhet. Vi trenger ikke implementere noe. Vi må
bare la være å ødelegge det, som er den ene måten dette går galt på: en FUSE-daemon som
svarer `ENOSYS` og får `fsync` til å lykkes gratis.

Presiseringen som må stå i spesifikasjonen: **`fsync` garanterer lokal holdbarhet, ikke
opplasting.** Data er varig lagret på denne maskinen og overlever omstart. Det er
nøyaktig det POSIX lover, og det er alt en applikasjon ber om. Opplasting er en
etterfølgende, asynkron tilstand — den skal være synlig i status-APIet, ikke smuglet inn
i `fsync`.

Dette bringer også debounce-mekanikken (referanseklientens #53, 900 s standard) i riktig
lys. Å vente til filen er stille er riktig — det fjerner tre kappløp ved kilden i stedet
for å reparere dem. Men det betyr at en endring lever bare på denne maskinen i opptil
15 minutter, og det **må** rammeverket si tydelig fra om: køen tømmes ved nedstenging,
ventende endringer telles som usendte i statusen, og «alt er synkronisert» vises aldri
over arbeid som ikke har forlatt maskinen.

*Garanti:* `fsync` returnerer suksess bare når dataene overlever `reboot -f`. Antall
usendte endringer er alltid korrekt, inkludert de som venter på stillhet.
*Test:* skriv, `fsync`, hardt strømbrudd (eller `echo b > /proc/sysrq-trigger` i VM) —
dataene er der. Og: en fil skrevet og slettet inne i stilleperioden når aldri skyen.

### 5.7 Hydrering som ikke stemmer med placeholderen

**Rammeverket eier den. Leseren skal aldri se delvis eller feil innhold.**

Placeholderens `st_size` settes fra servermetadata ved opprettelse. Endres filen i skyen
før noen leser den, hydrerer vi inn i en fil hvis størrelse er feil — og leseren står
allerede blokkert inne i `read()` når vi oppdager det. På et delta-synket filsystem er
dette ikke et hjørnetilfelle; det er tirsdag.

**Å korrigere størrelsen under en levende leser er ikke trygt.** Leseren har allerede
`stat`-et filen og kan ha dimensjonert en buffer etter det. Verre: er filen `mmap`-et,
gir en `ftruncate` nedover **SIGBUS** ved tilgang forbi den nye enden. Vi kan ikke
reparere oss ut av dette mens noen ser på.

**Regelen er derfor:**

> **En placeholder blir enten helt hydrert med det innholdet den lovet, eller den forblir
> uendret og leseren får `EIO`. Det finnes ingen tredje utgang.**

Placeholderen bærer skyens versjon i `user.hydration.etag` fra den ble opprettet.
Hydreringen verifiserer mot den, og de to tilfellene håndteres slik:

- **Avvik oppdaget før noe er skrevet** — provideren melder en annen lengde eller etag enn
  placeholderen lover. Ingenting skrives. Svar `FAN_DENY_ERRNO(EIO)`, marker inoden for
  metadata-resynk, og la neste delta-pass rette størrelsen. Leseren prøver igjen og møter
  da en placeholder som stemmer.
- **Avvik oppdaget underveis** — strømmen tar slutt for tidlig, eller etag endrer seg
  midt i. Filen er nå delvis fylt og *ser* hydrert ut. Punch hole tilbake til fullt
  dehydrert tilstand før det svares, deretter `FAN_DENY_ERRNO(EIO)`. En delvis fylt
  placeholder må aldri overleve svaret.

Dette er samme invariant som referanseklienten kom frem til for cachefiler — «en cachefil
er bare noen gang hel, nedlastinger lander via rename fra `.tmp`» — men håndhevet på
hydreringssiden, der `rename` ikke er tilgjengelig for oss fordi vi fyller en fil som
allerede har en identitet og en leser.

*Garanti:* en leser får aldri bytes fra en annen versjon enn den `stat` beskrev, og aldri
en delvis fylt fil. Ved uenighet mellom placeholder og sky vinner ingen av dem — leseren
får `EIO` og metadata resynkes.
*Test:* opprett placeholder med størrelse *N*, la provideren returnere *N−k* byte, les —
krev `EIO`, og krev at en påfølgende ærlig lesing gir hele objektet, slik at ingen rest
fra den mislykkede hydreringen overlevde. Samme test med etag endret mens strømmen er åpen.

### 5.8 En placeholder opptar ikke diskplass

**Kjernen eier den — hvis vi ikke rapporterer noe annet.**

> En fil som finnes som metadata alene rapporterer null allokerte blokker.

Denne sto ikke i spesifikasjonen da kontrakten ble skrevet. Den kom frem ved å kjøre
suiten mot referanseklienten, som rapporterer 128 blokker for en 64 KB placeholder den
ikke har innhold for.

Grunnen til at det hører hjemme i kontrakten: on-demand finnes for å spare disk, og `du`
er måten en bruker sjekker om det virket. En placeholder som rapporterer blokker for
innhold den ikke har, gjør at `du -sh ~/OneDrive` viser full skystørrelse — funksjonen kan
ikke observeres å virke selv når den gjør det. Verre for oss: enhver diskplass-policy vi
bygger oppå, inkludert utkastelse ved press, leser tall som er feil.

På et ekte filsystem er dette gratis — en sparsom fil rapporterer det den faktisk bruker,
og målingen i §2.4 viste nettopp `size=36 blocks=0`. En FUSE-klient må velge å rapportere
det, og kan like gjerne la være. Det er det samme mønsteret som resten av §3: kjernen har
allerede rett, userspace må gjenskape det.

*Garanti:* `st_blocks` er null for en dehydrert fil og reflekterer faktisk forbruk for en
hydrert.
*Test:* seed en 64 KB placeholder, `stat` — `st_size` 65536, `st_blocks` 0.

**Koster ingenting i den anbefalte arkitekturen.** En sparsom fil på ext4/btrfs/xfs
rapporterer allerede det den faktisk bruker — målingen i §2.4 ga `size=36 blocks=0` uten
at noe ble implementert for det. Å låse den inn utvider altså kontrakten uten å utvide
arbeidet, og den fanger en hel klasse feil hvis vi noen gang skulle vurdere en
implementasjon som ikke ligger på et ekte filsystem.

---

## 6. Hva vi taper, og hva kjernekode ville kjøpt

Spørsmålet ditt var om FUSE dekker 90 % uten kjernekode. Svaret er at **fanotify dekker
mer enn 90 %**, og her er de resterende prosentene, ærlig:

**1. Krever `CAP_SYS_ADMIN`.** Den lille privilegerte hjelperen. Dette er ikke til å
komme utenom i noen variant — FUSE-passthrough krever det samme. Kjernekode ville
kunne innføre en finere rettighet, men det er en oppstrøms-diskusjon som allerede pågår
(`TODO`-kommentaren i `backing.c`), ikke noe vi bør drive selv.

**2. Fail-open ved daemon-død — løst, men bare med et bestemt mønster.** Se §6a. Dette
var arkitekturens største åpne risiko og er nå målt og besvart.

**3. Blokkerende hendelser er et tilgjengelighetsansvar.** Henger daemonen, henger
tilgangen. Det trengs watchdog, timeout og en trygg feilvei (`FAN_DENY_ERRNO(EIO)` er
riktig svar, ikke å henge). Jeg bygget dette inn i testproben — auto-avslutning og
`FAN_ALLOW` på alle feilstier — nettopp fordi et blokkerende filter på et levende
filsystem ellers kan stoppe maskinen.

**4. Man kan ikke merke en katalog. Målt, og fellen er verre enn begrensningen.**

`probes/dirmark.c` prøver alle fire marketyper på samme katalog, med en fil rett i den og
en i en underkatalog:

| Marketype | `fanotify_mark` | `top.txt` | `sub/nested.txt` |
|---|---|---|---|
| `FAN_MARK_ADD` (inode) | **godtatt** | ingen hendelse | ingen hendelse |
| `FAN_MARK_ADD` + `FAN_EVENT_ON_CHILD` | godtatt | hydrert | **ingen hendelse** |
| `FAN_MARK_MOUNT` | godtatt | hydrert | hydrert |
| `FAN_MARK_FILESYSTEM` | godtatt | hydrert | hydrert |

Tre ting følger:

- **Et rent katalogmerke godtas og leverer ingenting.** Ikke en feilkode, ikke en advarsel
  — `fanotify_mark` returnerer 0 og hver dehydrerte fil leser som nuller. Det er samme
  familie som §6a og §6d: noe svarte «greit» på noe det ikke gjorde. Å bygge på det ville
  sett riktig ut helt til første ekte fil.
- **`FAN_EVENT_ON_CHILD` dekker bare direkte barn.** En synkmappe med underkataloger —
  altså enhver ekte synkmappe — er ikke dekket.
- **Bare `FAN_MARK_MOUNT` og `FAN_MARK_FILESYSTEM` virker.**

Mellom de to er `FAN_MARK_MOUNT` det riktige valget. `FAN_MARK_FILESYSTEM` på `/home`
ville sendt *hver eneste* filtilgang i brukerens hjemmeområde gjennom en blokkerende
handler — hele skadeområdet fra §6a, utvidet til alt brukeren eier.

**Konsekvens: synkmappen på eget monteringspunkt er et krav, ikke en anbefaling.** Det var
allerede andrelinjeforsvaret i §6a; nå er det også den eneste måten å få dekning på i det
hele tatt. Ett tiltak, to uavhengige begrunnelser.

### 6.4a Bind-mount holder ikke. Kravet er strengere enn «eget monteringspunkt».

Målt, fordi valget avgjør systemd-oppsettet. Et mount-merke er per `vfsmount`, og
spørsmålet er om noen *annen* sti når de samme filene.

| Oppsett | Dekning gjennom den tiltenkte stien | Finnes en omvei? |
|---|---|---|
| `mount --bind sync alt`, merk `alt` | ja | **ja** — original sti `sync/` gikk rett forbi, `blocks=0` |
| `mount --bind sync sync` (over seg selv) | ja, også underkataloger | **ja** — `mount --bind` av *forelderen* avdekker den skyggelagte katalogen |
| Eget btrfs-subvolum, montert separat | ja | **ja, hvis** btrfs-roten (`subvolid=5`) er montert |

Alle tre omveiene ble verifisert ved å lese en placeholder gjennom dem: `blocks=0`, ingen
hendelse levert, innholdet var nuller. Bind-mount over seg selv er altså ikke nok — en
ikke-rekursiv bind av forelderen er nok til å omgå det, og det er nøyaktig hva
container-runtimes og systemd-sandboxing (`BindPaths=`, `ProtectHome=`) gjør rutinemessig.

**Den riktige formuleringen av kravet er derfor ikke «eget monteringspunkt», men:**

> Ingen annen montering i systemet skal eksponere synkmappens filer.

Det er en egenskap ved hele maskinens monteringstabell, ikke ved vårt eget oppsett — og
det er verdt å si rett ut: **vi kan ikke håndheve det.** En bruker eller en container kan
lage en omvei etterpå, når som helst.

**Praktisk anbefaling: eget btrfs-subvolum.** På et vanlig Arch/CachyOS-oppsett er
btrfs-roten ikke montert — verifisert på denne maskinen, der `@`, `@home`, `@root`, `@srv`,
`@cache` og `@log` er montert hver for seg og `subvolid=5` ikke finnes i tabellen. Da har
et `@onedrive`-subvolum montert på `~/OneDrive` ingen annen sti. Det er billig, det passer
oppsettet som allerede finnes, og det krever ingen egen partisjon.

**Og siden vi ikke kan håndheve det, må vi oppdage det. Målt at vi kan.**
`probes/mntwatch.c` fanger den nøyaktige omveien over:

```
[mnt] ATTACH  -> 2 mount(s) now expose loop0
      …/hsm  (root /)
      …/hsm2 (root /)      <- omveien
[mnt] DETACH  -> 1 mount(s) now expose loop0
```

To ting proben avgjorde, som begge påvirker koden:

- **`FAN_REPORT_MNT` kan ikke kombineres med `FAN_CLASS_PRE_CONTENT`** — kallet gir
  `EINVAL`. Hydreringsgruppen kan altså ikke også overvåke monteringer; vakten trenger en
  egen deskriptor med `FAN_CLASS_NOTIF | FAN_REPORT_MNT`, merket med `FAN_MARK_MNTNS` på
  `/proc/self/ns/mnt`.
- **Hendelsens `mnt_id` er ikke en sannhetskilde.** Den er den 64-bits unike ID-en, ikke
  den gjenbrukte i felt 1 av `/proc/self/mountinfo`, og ved `DETACH` er monteringen borte
  og kan ikke slås opp i det hele tatt. Riktig form er å bruke hendelsen som *trigger til
  å se etter på nytt* — skann monteringstabellen og tell hvor mange monteringer som nå
  eksponerer filene. Det er namespace-riktig, tåler at hendelsen kommer før monteringen er
  synlig, og virker likt for attach og detach.

Det er samme prinsipp som §6d: vi kan ikke gjøre feilen umulig, men vi nekter å la den
være stille.

**5. Ingen ferdig utkastelsespolicy.** Kjernen sier ikke fra ved diskpress at den vil ha
plass. Vi må implementere dehydrering (`FALLOC_FL_PUNCH_HOLE` + fjerne ignore-merket)
etter egen policy — LRU, kvote, eller manuelt valg.

**Hva ville kjernekode kjøpt?** Realistisk bare punkt 1 og 5, og begge er små gevinster.
Et nytt filsystem eller en netfs-utvidelse ville gitt oss `fs/netfs` sine
delrekvisisjoner og en integrert utkastelsesvei — men til en pris som ikke står i
forhold. `ksmbd` er riktig referanse: år, med Samsung i ryggen, for noe med tydeligere
begrunnelse enn dette. Et hydrerings-filsystem ville i tillegg måtte forsvare hvorfor
det ikke bare er fanotify-HSM, mot vedlikeholdere som nettopp har mottatt fanotify-HSM
og som stilte det spørsmålet allerede.

**Anbefalingen er kategorisk: ingen kjernekode, ikke i v1 og sannsynligvis aldri.**

---

## 6a. Fail-open ved daemon-død

**Status: målt, og løst med et bestemt mønster som må inn i v1.**

Utgangspunktet er så ille som fryktet. Med hydreringsdaemonen `kill -9`-et leser en
dehydrert placeholder tilbake som nuller, med **exit 0**:

```
$ cat hsm/d.txt        # daemon drept med -9
                       # 36 nullbytes, ingen feil
[cat exit=0]
$ stat -c 'blocks=%b' hsm/d.txt
blocks=0
```

Til sammenligning, samme test på FUSE:

```
$ cat mnt/hydrated     # FUSE-daemon drept med -9
cat: mnt/hydrated: Transport endpoint is not connected
```

FUSE feiler lukket ved konstruksjon — `ENOTCONN` fordi tilkoblingen er borte. Naken
fanotify feiler åpent, fordi en fil uten et pre-content-merke bare *er* en sparsom fil.
Det er stille datakorrupsjon, og det er verre enn det vi erstatter.

**Løsningen: fanotify-gruppen lever så lenge én fd refererer den.** Del den privilegerte
hjelperen i to prosesser som deler gruppe-deskriptoren:

```
super  ── fanotify_init() + fanotify_mark()
   │       fork()
   │
   ├── worker   hydrerer, snakker med den uprivilegerte daemonen
   └── super    holder sin kopi av fd-en, rører den ikke
               ── ved worker-død: overtar løkka, svarer FAN_DENY_ERRNO(EIO)
```

Målt, med arbeideren `kill -9`-et og vakten i live:

```
[super] *** WORKER DIED (signal=9) - taking over, failing closed ***
$ cat hsm/w2.txt
cat: hsm/w2.txt: Input/output error
[cat exit=1]
$ stat -c 'blocks=%b' hsm/w2.txt
blocks=0
```

`EIO` i stedet for stille nuller, og filen forblir dehydrert. Det er samme feilklasse som
FUSE gir, og det er riktig oppførsel.

**Restrisikoen er at begge dør samtidig** — OOM-drap på hele cgroup-en, `SIGKILL` til
prosessgruppa, kjernepanikk. Da er vi tilbake til stille nuller. Forsvar i lag:

1. Vakten holder gruppa. Dekker krasj i arbeideren, som er der all kompleksiteten og
   dermed nesten all krasjrisiko sitter.
2. Vakten er nesten kodefri: åpne, merke, `fork`, `waitpid`, deny-løkke. Ingen HTTP, ingen
   parsing, ingen allokering i steady state. `OOMScoreAdjust=-1000` og
   `Restart=always` i systemd-enheten.
3. Synkmappen på eget monteringspunkt, med `BindsTo=`/`StopPropagatedFrom=` slik at
   monteringspunktet rives når enheten dør. Da er filene *utilgjengelige* i stedet for
   feil. Den dekker vinduet der ingenting av vårt kjører i det hele tatt.

   Dette punktet sto opprinnelig som andrelinjeforsvar. Etter målingen i §6.4 er det
   uansett obligatorisk: et katalogmerke leverer ingen hendelser, så eget monteringspunkt
   er den eneste måten å få dekning på. To uavhengige grunner til samme tiltak.

**En tredje feilmodus, funnet ved å måle etter.** Vakten dekker arbeiderdød *mellom*
hendelser. Den dekker ikke en hendelse arbeideren allerede har lest ut av køen:

```
[worker] HOLDING event unanswered (pid=644293)
[super]  *** WORKER DIED (signal=9) - taking over, failing closed ***
   leser: STILL BLOCKED ... rc=124   (drept av timeout, ikke returnert)
```

Hendelsen forlot køen sammen med arbeideren, så vakten ser den aldri og kan ikke svare.
Leseren henger ubundet. Filen forble dehydrert, så det er ingen korrupsjon — men en
uendelig henging er ikke et bedre utfall enn `EIO`.

**Lukkes ved at arbeideren publiserer hva den har i hendene.** Målt: en respons matches på
fd-nummer innenfor gruppen, ikke mot svarerens fd-tabell. Vakten kan derfor svare på en
hendelse den aldri selv leste:

```
[super] answering stranded event fd=4 for the dead worker: accepted
   leser: rc=1        (EIO, ikke henging)
```

Arbeideren skriver altså fd-nummeret til en delt plass før den gjør noe som kan henge, og
vakten svarer `FAN_DENY_ERRNO(EIO)` på alt som står der når arbeideren dør. Det er en
liten mekanisme, og uten den har fail-closed-designet et hull som ser ut som en hengt
maskin.

**Konformanstester som må finnes:** `kill -9` arbeideren mellom hendelser, les en
placeholder, krev `EIO`. `kill -9` arbeideren *mens* den holder en hendelse, krev `EIO` og
ikke henging. Og: drep begge, krev at monteringspunktet er borte innen N sekunder.

---

## 6b. Privilegieseparasjon

Dette er skissert i §4 og skal stå som et krav, ikke en illustrasjon:
**prosessen som holder `CAP_SYS_ADMIN` skal aldri se OAuth-tokenet.**

Grensesnittet mellom de to er hele poenget, så det må spesifiseres i v1:

| | Privilegert (`hydrated`) | Uprivilegert (klientdaemon) |
|---|---|---|
| Kjører som | root, `CAP_SYS_ADMIN` alene, ellers strippet | brukeren |
| Eier | fanotify-gruppa, skriving inn i placeholders | OAuth-token, Graph-API, sync-tilstand, database |
| Ser aldri | legitimasjon, nettverk, URL-er | fanotify-fd-en, andre brukeres filer |
| Kodemengde | 1–2k linjer, revideres på en ettermiddag | resten av klienten |

Protokollen over socketen skal være så kjedelig som mulig — det er der en
privilegie-eskalering ville bo:

- `hydrated` → daemon: «inode *X* på fsid *Y*, område *[o, o+n)*, forespurt av pidfd *P*».
  Aldri en sti. Aldri noe klienten kan påvirke til å peke et annet sted.
- daemon → `hydrated`: bytes, eller en feilkode. Ikke en filsti, ikke en fd, ikke en
  kommando.
- `hydrated` validerer at inoden ligger under det monteringspunktet den selv merket, før
  den skriver noe som helst.

Den privilegerte siden tar altså aldri imot en *destinasjon* fra den uprivilegerte —
bare innhold til en destinasjon den selv har bestemt. Det er den ene invarianten som
gjør at et kompromittert klientdaemon ikke blir root.

Presedensen er `fusermount3`, som er setuid root på denne maskinen av nøyaktig samme
grunn: en liten, revidert bro over et privilegiegjerde.

---

## 6c. Masselesing hydrerer alt

**Dette er den som avgjør om rammeverket er brukbart i praksis, og fanotify har ingen
innebygd forestilling om «ikke hydrer».** En nattlig `restic`-kjøring henter 300 GB.

Undersøkelsen ga fire lag, hvorav de to første fjerner det meste uten noen policyliste
i det hele tatt.

**Lag 1 — metadata hydrerer ikke. Målt.**

```
$ stat hsm/a.txt; ls -l hsm/a.txt; du -sh hsm/a.txt
$ stat -c 'blocks=%b' hsm/a.txt
blocks=0
```

`FAN_PRE_ACCESS` fyrer på innholdstilgang, ikke på `stat(2)`. Det betyr at `find`, `ls`,
`du`, `tree`, `rsync --dry-run` og førstepasset til de fleste indekserere er gratis. Det
er en vesentlig innsnevring av problemet: bare verktøy som faktisk leser bytes er i
faresonen.

**Lag 2 — `chattr +d` (nodump). Målt i praksis, og laget holder nesten ingenting.**

Flagget lar seg sette på btrfs (`------d---------------`), men det hjelper bare hvis
verktøyene leser det. Målt på de installerte, og slått opp for de to vanligste:

| Verktøy | Respekterer nodump |
|---|---|
| GNU `tar` | **nei** — ingen støtte i det hele tatt |
| `bsdtar` | bare med eksplisitt `--nodump` |
| `rsync` | **nei** |
| `borg` | bare med eksplisitt `--exclude-nodump` |
| `restic` | **nei** — støtter ikke `chattr`-attributter |
| `dump` | ja (flagget kommer derfra) |

Ingen av dem hopper over filene uten at brukeren ber om det, og de to som er vanligst på
en Linux-maskin i dag — `restic` og `rsync` — kan ikke gjøre det i det hele tatt.

**Dermed faller lag 2 som automatisk mitigering.** Det er verdt å sette flagget likevel:
det koster ingenting, og for den som kjører `borg --exclude-nodump` eller `bsdtar
--nodump` gjør det nøyaktig det man vil. Men det kan ikke bæres av. Konsekvensen er at
manifestet i §6d ikke er en ekstra trygghet — det er *den* mekanismen som gjør en backup
fullstendig, og lag 3 må dekke resten.

**Lag 3 — policy på systemd-enhet, ikke på pid. Verifisert ende til ende.**

`md->pid` alene er feil nøkkel: pid-er gjenbrukes, og oppslaget i `/proc/<pid>/` kappløper
med at prosessen dør. En pidfd pinner pid-en så lenge den er åpen, og gjør oppslaget
trygt. `probes/pidfd_cgroup.c` kjører hele veien og bekrefter at den virker:

```
[pidfd]   event->pid (racy key)  = 584386
[pidfd]   pidfd = 5 -> pid 584386
[pidfd]   comm   = cat
[pidfd]   exe    = /usr/bin/cat
[pidfd]   CGROUP = 0::/user.slice/.../app-com.anthropic.Claude-13945.scope

[pidfd]   event->pid (racy key)  = 584391
[pidfd]   pidfd = 5 -> pid 584391
[pidfd]   comm   = cat
[pidfd]   exe    = /usr/bin/cat
[pidfd]   CGROUP = 0::/system.slice/restic-probe.scope
```

Legg merke til hva dette faktisk viser. De to leserne er **identiske** på alt annet enn
cgroup: samme `comm`, samme `exe`, samme binærfil. En policy basert på kjørbar-sti kan
ikke skille dem — den ville enten sluppet gjennom backupen eller nektet brukeren sin egen
`cat`. Cgroup-en skiller dem rent: `restic-probe.scope` mot brukerens app-scope.

Det er nøyaktig skillet som betyr noe — `rsync` kjørt av backup-enheten mot `rsync` kjørt
av brukeren i et terminalvindu — og det er nå målt, ikke antatt. Cgroup er policy-nøkkelen.

**Lag 4 — nekt, aldri stille nuller.** `FAN_DENY_ERRNO(EPERM)` for en nektet leser. Da
logger backupverktøyet en feil i stedet for å skrive 300 GB nuller inn i arkivet sitt —
som er den virkelig ille utgangen, siden den ødelegger backupen stille.

**Og du har rett i at listen er et produkt.** Den skal ha en standardliste som dekker det
vanlige (restic, borg, duplicity, baloo, tracker, clamav, updatedb), en måte for brukeren
å legge til, og — viktigst — en **synlig logg over hva som ble nektet**. En bruker som
ikke skjønner hvorfor backupen klager, skal finne svaret på ett sted. Uten den loggen blir
policyen en usynlig felle i stedet for en funksjon.

Dette er også der Windows og macOS har en reell fordel: de har hint i APIet, så appen
sier selv «ikke hydrer». Vi må gjette utenfra. Gjetningen er god nok når den er
cgroup-basert og synlig, men den blir aldri like presis, og det bør stå i spesifikasjonen
som en kjent begrensning.

---

## 6d. Backup-kontrakten: nodump må aldri være stille

**En backup som hopper over dehydrerte filer inneholder ikke skyfilene dine.**

Det er kanskje riktig — de *er* i skyen — men en bruker som tror `restic` sikrer
`~/OneDrive`, og som ved gjenoppretting finner at hvert dehydrerte objekt manglet, har
mistet data av nøyaktig samme grunn som alle buggene i §5: noe svarte «greit» på
noe det ikke gjorde. `chattr +d` er teknisk elegant og semantisk en felle, og den må
behandles deretter.

**Regel: nodump settes aldri som bieffekt av dehydrering.** Den er en uttalt policy med
tre lovlige verdier, valgt ved oppsett, uten stille standard:

| `backup_policy` | Oppførsel | Konsekvens brukeren må se |
|---|---|---|
| `exclude` | nodump settes, backupverktøy hopper over | «*N* filer utelatt fra backup fordi de er skylagret» |
| `hydrate` | ingen nodump, backup leser og hydrerer alt | full backup, full nedlasting, full diskbruk |
| `deny` | ingen nodump, policyen nekter med `EPERM` | backupverktøyet feiler høyt og logger det |

Standard er `exclude` — men bare fordi de to andre er verre, ikke fordi den er trygg.
`hydrate` beseirer hele poenget med on-demand, og `deny` gjør at en nattlig backup feilar
i sin helhet. `exclude` er det minst gale valget, og prisen er at det **må** være synlig.

**Tre krav som følger, og som hører til kontrakten:**

1. **Tallet skal alltid stå i statusen.** Ikke i en loggfil, ikke bak et flagg. Samme sted
   som «alt er synkronisert» vises, skal det stå «412 filer utelatt fra backup fordi de er
   skylagret». Rammeverket eier telleren; klienten kan ikke la være å vise den.
2. **Valget tas ved oppsett, ikke arves.** Første gang synkmappen konfigureres skal
   spørsmålet stilles eksplisitt, med konsekvensen skrevet ut. En bruker som aldri tok
   stilling til dette har ikke tatt stilling til det.
3. **En manifest-fil som selv alltid er dense.** Rammeverket vedlikeholder
   `.hydration-manifest` i synkmappens rot: sti, sky-ID, størrelse, hash og versjon for
   hver dehydrerte fil. Den er liten, den er aldri dehydrert, og den blir dermed med i
   backupen. Da er backupen *fullstendig i den forstand som betyr noe* — en gjenoppretting
   kan hente innholdet igjen, i stedet for å oppdage et hull.

Punkt 3 er det som gjør `exclude` forsvarlig i det hele tatt. Uten manifestet er en backup
med nodump bare et hull med en teller ved siden av. Med det er den en fullstendig
beskrivelse av hva som fantes, og hvor det ligger.

**Og etter målingen i §6c er punkt 3 ikke lenger bare det som gjør `exclude` forsvarlig —
det er hele mekanismen.** Nesten ingen backupverktøy respekterer nodump uten at brukeren
ber om det, og `restic` kan ikke i det hele tatt. Det betyr at standardvalget `exclude` i
praksis oppfører seg som `hydrate` for de fleste: verktøyet leser filene, policyen i §6c
må nekte dem, og manifestet er det eneste som forteller hva som mangler.

**Konformanstest:** dehydrer *N* filer, kjør en backup med et verktøy som respekterer
nodump, og krev at (a) statusen rapporterer nøyaktig *N*, og (b) manifestet i backupen
lister alle *N* med hash som lar dem hentes igjen.

---

## 7. Kostnad

Forutsatt at klienten (auth, Graph-API, delta-sync) allerede finnes, som den gjør i
referanseimplementasjonen.

| Del | Omfang | Estimat |
|---|---|---|
| Privilegert hjelper, super/worker-delt | fanotify-løkke, områdehåndtering, fail-closed-vakt (§6a) | 2 uker |
| Privilegiegrense og protokoll | socket-protokoll, inode-validering, trusselmodell (§6b) | 1 uke |
| Tilstandslager | xattr-skjema, sky-ID ↔ inode, tilstandsmaskin | 1 uke |
| Placeholder/dehydrering | sparsom oppretting, `PUNCH_HOLE`, ignore-merker, nodump-flagg | 1 uke |
| Endringsdeteksjon og opplastingskø | debounce, avlysning, køtelling | 1–2 uker |
| Monteringspunkt-oppsett og systemd | subvolum, ordnet montering, `BindsTo`, OOM-herding | 1 uke |
| **Hydreringspolicy (§6c)** | pidfd→cgroup, standardliste, brukerkonfig, nektelseslogg | **2 uker** |
| **Konformanstestpakke (§5, §6a)** | de åtte invariantene, fail-closed, deterministiske kappløp | **3 uker** |
| Integrasjon mot referanseklienten | erstatte `crates/vfs` med provider-implementasjon | 1–2 uker |

**Sum: 12–15 uker** til en v1 som er nyttig for én ekte skyklient.

Estimatet er oppjustert fra 8–12 uker etter denne runden. Policyen og fail-closed-vakten
er ny, obligatorisk funksjonalitet, ikke pynt — og policyen har en produktdel (liste,
konfig, synlig logg) som ikke er ren programmering.

Testpakken er den største enkeltposten, og det er riktig. De seks buggene ble bare
fanget fordi noen skrev tester som holder en PUT åpen for å gjøre kappløpet
deterministisk. Det er den teknikken som må inn i rammeverket fra dag én — det er
forskjellen på et rammeverk som gjør buggene umulige og ett som bare flytter dem.

Kompetanse: dette er systemprogrammering i userspace. Ingen kjerneutvikling, ingen
oppstrøms-innsending, ingen ventetid på merge-vinduer. Det er en helt annen
risikoprofil enn `ksmbd`-sammenligningen.

---

## 8. Minste nyttige versjon

Én bruker, én konto, én maskin — men riktig.

**Med:**
1. Synkmappe på **eget btrfs-subvolum** (eller separat volum), montert kun med daemonen,
   merket med `FAN_MARK_MOUNT`. Ikke valgfritt: et katalogmerke leverer ingen hendelser
   (§6.4), et bind-mount har en omvei (§6.4a), og `FAN_MARK_FILESYSTEM` ville lagt hele
   `/home` under en blokkerende handler.
2. `FAN_MNT_ATTACH`-overvåking som sier fra hvis en ny montering eksponerer synkfilene.
   Kravet i §6.4a kan ikke håndheves, bare oppdages — og da skal det ikke være stille.
3. **Super/worker-delt privilegert hjelper med fail-closed-vakt (§6a).** Ikke valgfritt —
   uten den er arkitekturen usikrere enn FUSE.
4. **Privilegieseparasjon med spesifisert protokoll (§6b).** Root-siden ser aldri et token.
5. Placeholder: sparsom fil, riktig størrelse, sky-ID og modus i xattr, `chattr +d`.
6. Hydrering ved `FAN_PRE_ACCESS` — hele filen, ikke områder (se under).
7. `FAN_MARK_IGNORE_SURV` på hydrerte filer, så de koster null.
8. Endringsdeteksjon → debounce → opplasting, med de fem reglene i §5.
9. Dehydrering: `PUNCH_HOLE` + fjern ignore-merke + sett nodump. Manuelt utløst i v1.
10. **Hydreringspolicy (§6c):** pidfd→cgroup, standardliste, `FAN_DENY_ERRNO(EPERM)`,
   synlig nektelseslogg.
11. Konformanstestpakken. Alle åtte invariantene, pluss fail-closed-testen fra §6a.
12. `FAN_DENY_ERRNO(EIO)` ved nedlastingsfeil — aldri stille nuller.

**Utenfor v1, bevisst:**
- **Områdevis hydrering.** Hendelsen gir `offset`/`count`, men målingen viste at
  `count` er readahead-vinduet, ikke det appen ba om. Å hente hele filen ved første
  tilgang er riktig v1: det er hva CFAPI og File Provider gjør som standard, og det
  fjerner en hel klasse med delvis-innhold-bugger. Områdevis er en optimalisering for
  senere, når det finnes måledata som rettferdiggjør den.
- Multikonto, delte mapper, båndbreddegrenser, kryptering — som du sa.
- Automatisk utkastelse ved diskpress.
- Andre filsystemer enn ext4/btrfs/xfs.

---

## 9. Det jeg ikke fikk verifisert

I ærlighetens navn, siden dette skal være beslutningsgrunnlag:

- ~~Katalogmerker~~ — **lukket.** `probes/dirmark.c` måler alle fire marketyper: et rent
  katalogmerke godtas og leverer ingenting, `FAN_EVENT_ON_CHILD` dekker bare direkte barn.
  Eget monteringspunkt er dermed et krav (§6.4).
- ~~Bind-mount~~ — **lukket, og svaret ble strengere enn spørsmålet.** Verken bind til en
  egen sti eller bind over seg selv holder; begge har en omvei som leverer nuller (§6.4a).
  Kravet er at ingen annen montering eksponerer filene, og det kan vi ikke håndheve — bare
  oppdage, med `FAN_MNT_ATTACH`. Jeg har **ikke** kjørt en probe på selve
  `FAN_MNT_ATTACH`-abonnementet; det er neste lille probe.
- ~~`FAN_MARK_IGNORE_SURV`~~ — **lukket.** `probes/ignoremark.c`: godtatt, undertrykker,
  og overlever endring. Ytelsespåstanden står.
- Jeg testet **ikke** mmap-hydrering eller `truncate`-hydrering. Kildekoden har hookene
  (`fsnotify_mmap_perm`, `fsnotify_truncate_perm`); jeg har ikke sett dem fyre.
- ~~Hendelser under behandling ved arbeiderdød~~ — **lukket, og det var et ekte hull.**
  En hendelse arbeideren allerede hadde lest ut av køen etterlot leseren hengende
  ubundet; vakten kunne ikke svare på noe den aldri så. Lukkes ved at arbeideren
  publiserer fd-nummeret sitt — responser matches på nummer innenfor gruppen. Se §6a.
- ~~`FAN_REPORT_PIDFD`~~ — **lukket.** `probes/pidfd_cgroup.c` henter pidfd fra hendelsen,
  slår opp pid og leser cgroup. Verifisert at cgroup skiller to lesere med identisk `comm`
  og `exe`. §6c hviler ikke lenger på en antakelse.
- ~~Nodump i praksis~~ — **lukket, og svaret var «nesten ingen».** GNU `tar` og `rsync`
  har ingen støtte; `bsdtar` og `borg` bare med eksplisitt flagg; `restic` ikke i det hele
  tatt. Lag 2 i §6c faller som automatisk mitigering, og manifestet i §6d bærer
  fullstendigheten alene.
- §5.7 er skrevet ut fra hva som er trygt (SIGBUS-risikoen ved `ftruncate` under en
  `mmap`-et leser er reell og velkjent), men jeg har **ikke** kjørt en probe som
  demonstrerer avviks-tilfellet ende til ende. Den bør inn i konformanstestpakken før §5
  låses.
- Ytelsestallene i §2.3 er på tmpfs med en triviell C-daemon. En ekte Rust/tokio-daemon
  med databaseoppslag er vesentlig tregere, og på NVMe ser forholdet annerledes ut.
  Tallene viser strukturen — passthrough fjerner userspace-rundturen — ikke absolutte
  verdier du kan planlegge kapasitet etter.
- Kjernekilden jeg leste var `torvalds/linux` master, ikke nøyaktig 7.1.6-cachyos.
  Overskriftsfunnene (`CAP_SYS_ADMIN` i `backing.c`, `SB_I_ALLOW_HSM` i de tre
  filsystemene, `FOPEN_PASSTHROUGH_MASK`) stemmer med den lokale uapi-headeren og med
  målingene, så jeg regner dem som pålitelige.

Alle prober kjørte i scratchpad-området på isolerte monteringspunkter (loopback-btrfs
for HSM-testen, aldri på `/home`), og alt er ryddet opp — ingen monteringspunkter,
loop-enheter eller prosesser står igjen.

---

## 10. Neste steg

Hvis du er enig i retningen, er den naturlige rekkefølgen:

To spor, parallelt.

**Spor A — konformanstestpakken.** ✅ **Bygget og kjørt mot referanseklienten.**

`conformance/` inneholder invariantene skrevet mot en `Harness`-trait som ikke kjenner
noen implementasjon, og `adapters/onedrive-reference/` kjører dem mot en ekte FUSE-mount,
ekte sync-motor og ekte SQLite, mot en falsk Graph-API suiten kan styre.

Suiten ble først kjørt mot `f1f090c` — klienten som den var da kontrakten ble skrevet —
og deretter mot `a6312a8`, der de tre funnene er fikset og merget.

| Invariant | `f1f090c` | `a6312a8` |
|---|---|---|
| 5.1 identitet er stabil | PASS | PASS |
| 5.2 størrelse er lokal sannhet | PASS | PASS |
| 5.3 modus overlever dehydrering | **FAIL** | PASS |
| 5.4 atomisk lagring beholder navnet | PASS | PASS |
| 5.5 sletting slår opplasting i lufta | PASS | PASS |
| 5.6 `fsync` lyver ikke | PASS | PASS |
| 5.7 hydreringsavvik feiler lukket | **FAIL** | PASS |
| 5.8 placeholder opptar ikke disk | **FAIL** | PASS |
| 6a arbeiderdød feiler lukket | N/A | N/A — ingen separerbar arbeider |

**Førstekjøringen er den interessante.** Fem av åtte passerte allerede, inkludert 5.4 og
5.5 — nøyaktig de to buggene klienten fikset i #51 og #52. Suiten bekreftet uavhengig at
de fiksene holdt, og skilte dermed det som var løst fra det som ikke var, i stedet for
bare å anklage.

De tre som feilet er fikset i
[#55](https://github.com/franzjeger/OneDriveForLinux/pull/55). 5.3 var `setattr` som tok
imot en modusendring og forkastet den — og, mindre synlig, at modusen ble foreldreløs når
opplastingen adopterte den ekte OneDrive-ID-en. 5.7 var en nedlasting som endte for tidlig
og ble servert som en kort fil. 5.8 var `blocks` regnet ut fra `size`.

**Den andre halvdelen av 5.3 er argumentet for suiten.** Den var ikke synlig ved
kildelesing; den dukket opp fordi testen fortsatte å feile etter at den åpenbare fiksen
var på plass. Det er en bugklasse — noe som virker helt til en asynkron operasjon fullfører
— som klienten har hatt fire av tidligere, og som ingen kodegjennomgang fanget.

**Spor B — probene som kan velte arkitekturen (§9).** ✅ **Alle kjørt.**

| Probe | Svar |
|---|---|
| pidfd→cgroup | virker; cgroup skiller lesere som er identiske på `comm` og `exe` |
| Katalogmerker | går ikke — merket godtas og leverer ingenting (§6.4) |
| Bind-mount | holder ikke — hver variant har en omvei (§6.4a) |
| `FAN_MNT_ATTACH` | virker, men trenger egen gruppe; hendelsen er en trigger, ikke et oppslag |
| `FAN_MARK_IGNORE_SURV` | virker, og overlever endring — ytelsespåstanden står |
| Hendelser under behandling | var et ekte hull; lukket ved å publisere fd-nummeret (§6a) |
| Nodump i praksis | nesten ingen verktøy respekterer det — lag 2 faller (§6c) |

Ingen av dem veltet arkitekturen. Tre av dem gjorde et krav strengere, og to fant en
stille feil av samme familie som de åtte invariantene: noe som svarte «greit» på noe det
ikke gjorde.

**Deretter:** den privilegerte hjelperen — super/worker fra §6a — som den minste tingen
som får fail-closed-testen og den første invarianten fra spor A til å passere.

Prober og loggene fra denne undersøkelsen ligger i scratchpad-området
(`ptprobe.c`, `hsmprobe.c` og målelogger) hvis du vil kjøre dem selv.

---

## 11. Bygge rammeverket, eller fikse klienten?

**Anbefaling: fiks de tre funnene i klienten nå. Bygg rammeverket bare som en bevisst
produktsatsing — ikke som en redningsaksjon.**

Konformanskjøringen ga informasjon designdokumentet ikke hadde da §1 ble skrevet, og den
peker en annen vei enn jeg ventet.

**Klienten er nærmere riktig enn den så ut.** Fem av åtte invarianter passerer, og de to
som passerer og var vanskeligst — atomisk lagring og sletting under opplasting — er ekte
distribuerte kappløp som ingen arkitektur gir gratis. De ble løst i userspace, i FUSE, og
fiksene holder under en uavhengig test som ikke var skrevet av den som fikset dem.

**De tre som feiler er alminnelige bugger, ikke arkitektoniske umuligheter.** Hver av dem
er dager, ikke uker:

| Funn | Hva som skal til i FUSE |
|---|---|
| 5.3 modus | Lagre modus i databasen og svare med den fra `getattr`. `setattr` tas allerede imot; den forkastes bare. |
| 5.7 hydreringsavvik | Verifiser lengde og etag før innholdet serveres; forkast delvis nedlasting i stedet for å levere den. |
| 5.8 blokker | Rapporter `blocks = 0` for placeholders i `getattr`. |

**Og fanotify-veien er ingen trygg havn.** Tre av de fire siste probene fant en stille
feil av nøyaktig den familien dette prosjektet finnes for å drepe: et katalogmerke som
godtas og leverer ingenting, en bind-mount som ser ut til å dekke og har en omvei, en
arbeiderdød som henger leseren i stedet for å svare. Alle er løsbare — men de er *nye*
ting å få rett, og de kommer i tillegg til det klienten allerede har fått rett.

Det er verdt å si tydelig, siden §1 og §3 argumenterer motsatt vei: **det stemmer fortsatt
at kjernen eier POSIX-kontrakten bedre enn vi kan, men det er en mindre del av totalen enn
dokumentet antok.** Rammeverket flytter hvilke ting man må få rett — det fjerner ikke
listen. POSIX-delen forsvinner; monteringstopologi, privilegiedeling, fail-closed-tilsyn
og hydreringspolicy kommer i stedet, og de tre siste finnes ikke i en FUSE-klient i det
hele tatt.

### Hva rammeverket faktisk kjøper

To ting, og begge er langsiktige:

1. **Bugklassene blir umulige, ikke fikset.** Fem av åtte invarianter er gratis på et ekte
   filsystem. Over år med endringer er det forskjellen på å ikke kunne introdusere feilen
   og å måtte teste for den hver gang.
2. **Null kostnad i datastien.** Målt: en hydrert, ignore-merket fil er en vanlig
   btrfs-fil. Ingen daemon, ikke engang de 8 % FUSE-passthrough koster.

### Beslutningsregelen

- **Er OneDrive-på-Linux produktet?** Fiks de tre. 12–15 uker på et rammeverk er ikke
  forsvarlig for tre bugger som tar dager.
- **Er *skyfiler på Linux* produktet** — flere leverandører, eller et fundament andre kan
  bygge på? Da er rammeverket riktig, og da er det verdt hele prisen i §7.

Det er en produktbeslutning, ikke en teknisk. Teknisk er begge veier farbare, og denne
undersøkelsen har gjort dem begge tryggere enn de var.

### Uansett hvilken vei

Konformanssuiten er det som gjør begge trygge, og den er ferdig. Den er også det eneste
her som ikke må velges bort: den kjører mot klienten i dag, den kjører mot rammeverket
hvis det bygges, og den overlever at valget gjøres om.
