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

## 6a-bis. En hengt arbeider er verre enn en død arbeider

Funnet under implementasjonen, og det utvider §6a på en måte designet ikke
forutså.

**En prosess som står i en pre-content-hendelse kan ikke drepes med et signal.**
Hendelsen må besvares først. Målt: `SIGKILL` mot en blokkert leser gjør
ingenting; prosessen blir reapbar først når noen svarer på hendelsen, eller når
gruppen lukkes.

Konsekvensen er ubehagelig. §6a løser at arbeideren *dør* — vakten holder gruppen
og nekter. Den løser ikke at arbeideren **henger**: da står hendelsen ubesvart,
prosessen kan ikke drepes, og gruppen kan ikke lukkes fordi den døde prosessen
fortsatt holder sin deskriptor. Hver senere operasjon på monteringen blokkerer,
inkludert `ftruncate` og filoppretting. «Start daemonen på nytt» er ikke et
tilgjengelig svar.

Det skjedde flere ganger under utviklingen, og hver gang var symptomet det samme:
monteringen så frisk ut, `mountpoint` sa ja, `touch` virket, og alt annet hang.

**Hva som måtte inn i v1 — nå bygget og testfestet** (`tests/deadlines.rs`):

- **Tidsfrist per hendelse.** Hentingen kjører på egen tråd og arbeideren venter
  på en kanal, så en `Fetch` som aldri returnerer koster leseren `EIO` etter
  fristen framfor å holde den for alltid. Fristen kan ikke håndheves ved å be
  klienter respektere en — det er nettopp den slags regel rammeverket finnes for
  å slippe. Standard 30 s.
- **Vakten overvåker fremdrift, ikke liv.** Den delte siden bærer nå en teller
  arbeideren øker for hver besvarte hendelse. Holder arbeideren en hendelse uten
  at telleren har flyttet seg på 90 s, behandles den som død. Bare en arbeider
  som *holder noe* kan stå fast; en ledig arbeider gjør heller ingen fremdrift,
  og å rive ned monteringen hver gang ingen leser ville vært verre enn feilen.
- **Rekkefølgen ved nedrivning er selve poenget.** Signal først: en arbeider som
  står i en nettverkshenting dør der. Gjør den ikke det, står den i en
  pre-content-hendelse den selv utløste (§6a-ter), og da når ingen signaler den —
  den slippes først når hendelsen besvares. Derfor kommer svaret *etter* drapet,
  ikke før.
- **Monteringen rives ned uten å feile åpent.** Å avslutte prosessen ville lukket
  gruppen, og en montering uten gruppe feiler *åpent*: hver placeholder blir en
  kilde til nuller. Så monteringen kobles fra med `MNT_DETACH` mens prosessen
  blir stående og nekter alt som allerede er underveis, og avslutter først når
  det har vært stille i 10 s. `BindsTo=` dekker det samme fra systemds side;
  hjelperen gjør det selv i tillegg, så garantien ikke avhenger av å ha blitt
  utrullet med de medfølgende enhetene.

**En feil den første versjonen innførte, verdt å skrive ned fordi den var
usynlig.** Telleren over bomskudd kortsluttet *før* forespørselen ble sendt, så
ingen svar kunne komme, så telleren kunne aldri nullstilles. Tre bomskudd gjorde
monteringen til øyeblikkelig `EIO` for alltid — servert av to prosesser som så
helt friske ut, med vaktens stallvakt som aldri ville fyre, fordi en arbeider som
nekter raskt ikke står fast. Et avbrudd som ser ut som et fungerende system.

To ting rettet det:

- **Fastlåsingen er reversibel.** Forlatte hentinger kjører videre, og et svar
  fra en av dem er bevis på liv. Det dreneres nå der kortslutningen står, så en
  henter som kommer tilbake blir brukt igjen.
- **Den er tidsbegrenset.** Blir den værende ubesvart i fem minutter, stopper
  arbeideren. Hver leser er allerede besvart — løkken kommer bare hit mellom
  hendelser — så ingenting henger, og vakten river ned monteringen derfra. Det er
  §6a-bis' tredje krav nådd via den andre veien.

**Én begrensning som står igjen, målt og bevisst.** Hentinger er serialisert —
én forbindelse til synk-daemonen, én utestående forespørsel. En henting som har
gått over fristen holder derfor køen til den faktisk returnerer, og lesinger bak
den får `EIO` framfor innhold. Det er en *degradering*, ikke en låsing, og det er
skillet §6a-bis handler om: hver leser besvares raskt. Å fjerne det krever
pipelining, som protokollens `id`-felt allerede åpner for og transporten ennå
ikke implementerer.

---

## 6a-ter. Å skrive inn i en merket montering er prosjektets skarpeste kant

Samme feil har oppstått **seks ganger, i seks forkledninger**, hver gang av noen
som visste om de foregående:

| Hvor | Hva som ble skrevet |
|---|---|
| Arbeiderens hydrering | åpnet stien på nytt for å fylle filen |
| Dehydrering | punchet hull uten et ignore-merke |
| Utkastelsestesten | fylte filen etter at monteringen var merket |
| `eventtrace`-proben | laget placeholderen etter markeringen |
| Delta-synk | måtte gi en ny placeholder størrelse inne i monteringen |
| `placeholder_creation`-testen | dehydrerte *etter* markeringen — i testen som finnes for å fange nettopp dette, og den låste hele suiten i 300 s |

Formen er alltid den samme: **en skriving inne i en merket montering, utført av
den eneste prosessen som kunne besvart hendelsen den utløser.** Resultatet er en
permanent låsing, uten feilmelding, med en handler som ser helt frisk ut i
`poll()`.

Fire ganger er ikke fire slurvefeil. Det er formen på APIet, og rammeverket må
gjøre den umulig å treffe framfor å advare mot den:

- Skriv aldri ved å åpne en sti inne i den merkede monteringen. Bruk hendelsens
  egen fd, som ikke avskjæres — det er derfor kjernen gir den fra seg.
- Der en sti må åpnes, skal ignore-merket settes først og fjernes etterpå, og de
  to skal ligge inne i samme funksjon. `evict()` gjør det; ingen skal kunne
  sekvensere det selv.
- Testrigger skal opprette og fylle filer **før** monteringen merkes.

### Den sjette forkledningen, og hvorfor den fikk et eget svar

De fem første var feil. Den sjette var et krav: delta-synk **må** opprette
placeholdere, og å opprette en placeholder er å gi en fil størrelse. Den kunne
altså ikke bare unngås.

De to åpenbare utveiene var begge dårligere enn de så ut:

- **La hjelperen opprette filen på en sti daemonen velger.** Det er en ekte
  privilegieeskalering, ikke en teoretisk: root går en sti den uprivilegerte
  siden kontrollerer (symlink/TOCTOU), resultatet eies av root, og siden
  `mode` settes av den som oppretter, blir `06755` til en setuid-root-binær hvis
  innhold *den samme daemonen* leverer etterpå.
- **La hjelperen låne ut et ignore-merke** på en inode daemonen peker ut. Det er
  evnen til å få en vilkårlig fil til å lese som nuller — nøyaktig feilen
  rammeverket finnes for å hindre.

`O_TMPFILE` fjerner dilemmaet i stedet for å forvalte det. Placeholderen bygges
på en **anonym inode uten navn**, og `linkat` gir den navn først når den er
ferdig. Målt på 6.17 (`probes/tmpfile.c`):

```
events after create:            0
events observed while sizing:   1   <- nlink=0, size=0
events during linkat:           0
result: size=4096 blocks=0, dehydrated mark present
```

Størrelsessettingen er altså **ikke** stille. Den ene hendelsen den utløser
svarer arbeideren på med én smal regel — men hvilken regel er hele poenget, og
det første forsøket var utnyttbart.

**Det som ikke virket, og hvorfor det er verdt å skrive ned.** Første versjon
slapp gjennom en inode med `nlink == 0` som bar et merke `user.hydration.building`,
satt av daemonen mens den bygget. Argumentet var at en inode uten navn ikke kan
åpnes, så ingen leser kan bli servert feil. Argumentet er usant: `nlink == 0`
betyr *uoppnåelig via et nytt navn*, ikke *ingen åpne deskriptorer*. En fil som
åpnes og så avlinkes har `nlink == 0` med en leser parkert i `read()`. Det eneste
som skilte det trygge tilfellet fra det farlige var merket — og et `user.*`-xattr
kan settes av enhver prosess med filens uid, som i denne trusselmodellen er
motstanderen. Målt angrep:

1. angriper setter merket på en ekte placeholder den eier — ingen privilegier
2. offeret åpner og leser; lesingen blokkerer på pre-content-hendelsen
3. angriper avlinker filen — ikke en innholdstilgang, så ingen hendelse
4. arbeideren ser `nlink == 0` og merket, og slipper gjennom uten å hydrere
5. offeret får nuller og arkiverer dem som innhold

Det omgikk også §6c fullstendig, siden snarveien lå foran policy-porten: en
backup som skulle vært nektet med `EIO` — det trygge svaret — ble i stedet
sluppet gjennom med nuller.

**Regelen som holder** bruker ingen påstand, bare en egenskap kjernen selv
rapporterer: **`nlink == 0 && st_size == 0`.** Hendelsen fyrer *før* `ftruncate`
tar effekt, så inoden er fortsatt tom når arbeideren ser den (målt). En tom fil
har ingen byte noen kan bli servert i stedet for ekte innhold, så å slippe den
gjennom er ikke en snarvei forbi hydrering — det er nøyaktig det hydrering av en
tom fil ville gjort. `nlink == 0` bærer ikke sikkerheten; den holder bare regelen
til tilfellet som trenger den.

Forskjellen er ikke kosmetisk. Et merke er noe noen *sier*; en størrelse er noe
filen *er*. Det finnes ingenting her for en angriper å hevde.

Gevinsten er strukturell, ikke bare praktisk: **det finnes ingen destinasjon i
protokollen i det hele tatt.** §6b er ikke lenger en regel noen må huske å følge
på den privilegerte siden — den privilegerte siden får aldri se en sti.

En presisering, siden den første formuleringen var for sjenerøs: opprettelsen
ligger *ikke* helt på den uprivilegerte siden. `ftruncate` utløser fortsatt en
hendelse som bare hjelperen kan svare på, så daemonen kan ikke opprette en
placeholder alene inne i en merket montering. Det som er sant er smalere, og
det er det som betyr noe: **hjelperen får aldri en destinasjon, og tar ikke
imot noen instruksjon under opprettelsen.** Den svarer på det kjernen forteller
den om en fil den selv har fd-en til.

Det samme funnet tvang fram en annen retting. Arbeideren slo opp
placeholder-merket via *stien* hendelsen løste til. En placeholder som avlinkes
mens den er åpen har ingen sti, og ble derfor nektet med `EIO` selv om innholdet
var fullt hentbart. Arbeideren jobber nå fra hendelsens fd (`fgetxattr`/`fstat`),
og stien brukes bare til det den faktisk trengs til: ignore-merket og
avslagsloggen. Det fjerner samtidig en TOCTOU, siden en sti kan endres mellom
oppslag og bruk.

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

### Hvem grensen faktisk går mot

Fiksen over reiste et spørsmål den ikke besvarte, og det må stå eksplisitt i
kontrakten framfor å ligge underforstått: **er en kompromittert `hydration-sync`,
som kjører som brukeren, i omfang for garantien om at ingen lesing stille
returnerer nuller?**

Anbefalingen er **nei**, og grunnen er ikke bekvemmelighet:

- Merket `user.hydration.dehydrated` er det som forteller arbeideren at en fil er
  en placeholder. Alle `user.*`-attributter kan skrives av enhver prosess med
  filens uid. Fjernes merket, konkluderer arbeideren med at innholdet allerede er
  der, og serverer hullet. **Målt og testfestet**
  (`stripping_the_placeholder_mark_does_not_permanently_disable_interception`).
- Det er ingen ny evne. Den samme prosessen kan skrive nuller rett over filen.
  Forskjellen er at merkefjerning er stillere: ingen byte skrives, så mtime står
  stille, ingen opplasting utløses, og ingen disk brukes.
- Å lukke det krever at merket ligger i `trusted.*`, som krever `CAP_SYS_ADMIN` å
  skrive. Da må hjelperen sette merket, altså delta i opprettelsen — og da er vi
  tilbake til nøyaktig eskaleringen §6a-ter nettopp fjernet: root som går en
  daemon-valgt sti, og `mode = 06755` som blir en setuid-root-binær.

Grensen rammeverket **faktisk** håndhever er derfor smalere, og verdt å si rett
ut:

> Den privilegerte hjelperen blir aldri en skriv-hvor-som-helst-som-root-primitiv,
> og en lesing returnerer aldri nuller på grunn av **svikt** — daemon-død,
> nettverksfeil, hengt arbeider, policy-avslag. Mot en *ondsinnet prosess med
> brukerens egen uid* er ikke rammeverket et forsvar, fordi den prosessen eier
> filene uansett.

Det som likevel ble gjort, fordi det er billig og begrenser skaden: arbeideren
setter **ikke** lenger et permanent ignore-merke på en fil som oppgir størrelse
men ikke opptar disk. Uten det ble én xattr-fjerning til stille nuller *for
alltid*, uten videre involvering og uten noe å observere. Nå varer skaden bare så
lenge merket er borte, og filen leges når merket kommer tilbake. Prisen er en
rundtur per lesing av en ekte sparse hydrert fil, som er sjelden og er den trygge
retningen å ta feil i. Det når ikke små filer — btrfs lagrer dem inline, så en
strippet liten placeholder oppgir fortsatt blokker.

**Hvis dette svaret er feil**, er konsekvensen en egen designrunde: merket må
flyttes til `trusted.*`, hjelperen må sette det, og opprettelsen må tilbake over
privilegiegrensen med de kostnadene §6a-ter beskriver. Det er ikke en liten
endring, og derfor står valget her framfor i en commit-melding.

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

## 6e. Rammeverkets egne filer er aldri brukerens

Én regel, og den er lett å utelate fordi ingenting feiler høyt når man gjør det:

> **Rammeverkets egne filer synkes aldri.**

Manifestet skrives om hver gang antallet placeholdere endrer seg. Behandles det
som brukerinnhold, blir det en helt vanlig lokal fil: endringsdeteksjonen ser
skrivingen, køen debouncer den, opplastingen gir den en sky-id, neste delta-pass
henter den ned igjen, og omskrivingen etter det starter på nytt. Ingenting
feiler. De to endene slutter bare aldri å snakke om en fil brukeren aldri har
hørt om.

Verre i den andre retningen: et skyobjekt kunne hete `.hydration-manifest`, og et
delta-pass ville da erstattet §6d-mekanismen med en placeholder — filen som
forteller en gjenopprettende bruker hva som mangler, ville selv blitt en fil uten
innhold. `safe_join` avviser det nå, framfor å døpe det om: en omdøpt sti betyr
stille noe annet enn det skyen sa.

Predikatet ligger i den delte krata av samme grunn som xattr-navnene. Skanningen,
manifest-byggeren, delta-passet og endringsvakten trenger alle det samme svaret,
og fire kopier av det er hvordan de blir uenige.

---

## 6f. `nodump` har en eier

Flagget hadde en setter og ingen livssyklus. Målt først (`probes/nodump.c`,
6.17, btrfs), fordi alle tre svarene former koden:

```
set nodump: completed, events fired: 0
survives a hole punch:            yes
survives being written through:   yes
```

- **Ingen hendelse** er det som gjør det trygt å sette inne i `evict()`, som
  kjører i den merkede monteringen i prosessen som svarer på hendelser (§6a-ter).
  Flagget settes derfor rett ved siden av dehydreringsmerket, i samme funksjon.
- **Overlever å bli skrevet gjennom** er den viktige: hydrering rydder det *ikke*
  av seg selv. Uten et eksplisitt steg ville en hydrert fil fortsatt blitt hoppet
  over av enhver backup som respekterer flagget — §6d-skaden inn bakveien, altså
  innhold som bare finnes her og likevel er utelatt fra backupen. Det ryddes nå i
  `hydrate_fd`, gjennom hendelsens fd, i samme operasjon som fyller filen.

Ryddingen er ubetinget og ikke betinget av at vi satte det selv. Den smale
kostnaden er en bruker som har satt `nodump` for hånd på en fil som senere viser
seg å være en placeholder: hydrering fjerner flagget deres. Det bommer i retning
*mer* data i backupen, som er retningen §6d finnes for å beskytte.

`Backup::Exclude` / `Backup::Include` er nå et argument til `evict()` uten
standardverdi, fordi det ikke finnes en trygg en — å utelate betyr at backupen
stille mangler innholdet, å inkludere betyr at ethvert backup-sveip drar ned hele
disken.

---

## 6g. Endringsdeteksjon: kanalen er en optimalisering, aldri en autoritet

Vakten fantes og var testet, men ingen binær opprettet en. En lokal redigering
ble derfor aldri lastet opp i en ekte kjøring. Det er nå koblet, og formen er
styrt av to målinger.

**Sending kan ikke skje i hendelsesløkken.** En AF_UNIX-strøm tar imot ~278
korte meldinger på standard `SO_SNDBUF` før avsenderen blokkerer — kjernen
belaster en hel skb per liten sending, ikke nyttelasten. En arbeider som
blokkerer i `write()` slutter å svare på pre-content-hendelser, og verre: vakten
fra §6a-bis ser det ikke. Stallvakten fyrer på *å holde en hendelse uten
fremdrift*, og en arbeider som blokkerer mellom hendelser holder ingenting. Den
klassifiseres som ledig, for alltid, mens hver leser på monteringen henger.
Monteringen ser frisk ut. Ingenting kommer seg.

Derfor tre tråder, alle startet etter `fork`:

```
drainer  ── leser varselgruppen, folder hver hendelse inn i et skittent sett
              blokkerer aldri på annet enn en mutex
sender   ── bytter ut settet, skriver én samlet linje
              får gjerne blokkere; blokkerer bare seg selv, mens settet absorberer
arbeider ── svarer på pre-content-hendelser, rører ingen av delene
```

Å folde inn i et sett er ikke en påplussing: det er den samme sammenslåingen
kjernen allerede gjør. Målt — 10 000 vekslende skrivinger til to filer ga to
hendelser, med `MODIFY` og `CLOSE_WRITE` slått sammen per objekt. Settet
fortsetter det forbi kjernens grense på 16 384 objekter, og størrelsen er
begrenset av antall filer på monteringen, ikke av hvor mye som skrives.

**Ingen destruktiv sti får stole på stillhet.** Endringsdeteksjon er tapsutsatt
oppstrøms for socketen uansett hva som bygges: varselkøen renner over på under to
sekunder under en arkivutpakking, `truncate(2)` gir ingen hendelse i det hele
tatt, og redigeringer mens hjelperen er nede gir aldri noen. Hvert av de hullene
ender samme sted — i et `place()` som døper en placeholder over innhold som ikke
finnes noe annet sted, og teller det som en vellykket oppdatering.

Så filen spørres direkte. På de tre øyeblikkene rammeverket selv gjør innhold
rent — plassering, hydrering, opplasting — skriver det ned størrelsen og mtime-en
det nettopp produserte (`user.hydration.stamp`). Alt annet som skriver flytter
mtime, og uenigheten er synlig uten å ha blitt fortalt om. Delta-passet nekter nå
å skrive over en fil som er `Dirty`, uavhengig av hva køen sier.

**To regler kom ut av gjennomgangen etterpå, begge fordi den første versjonen
brøt dem.**

*Et pass uten nyheter må ikke gjøre noe.* `apply` hadde ingen «allerede
oppdatert»-sjekk, så en upsert for en sti som fantes lokalt falt gjennom alle
vaktene og landet ubetinget i `place()`. En ekte delta-strøm ekkoer dine egne
opplastinger tilbake på neste side, og `Discover` lover selv at en full listing
oppfører seg som en inkrementell — så det er ikke et eksotisk inndata, det er det
normale. Konsekvensen var ikke churn, men at en fil brukeren nettopp hadde
skrevet og fått lastet opp ble gjort om til en placeholder sekunder senere. På en
maskin som er offline neste morgen er det innholdet deres, borte. Identitet
sjekkes nå først, så størrelse, så versjon — og størrelse uansett hva etag-ene
sier, fordi en leverandør som melder samme versjon med annen størrelse motsier
seg selv, og å tro etag-en framfor bytene ville etterlatt en placeholder som
lover en lengde objektet ikke har.

*Stempelet må beskrive innhold som ikke er nyere enn det som faktisk ble sendt.*
Opplastingen stemplet fra filen slik den var *etterpå*. En redigering som landet
under overføringen ble dermed velsignet som sendt — den ville aldri blitt lagt i
kø igjen, og neste endring fra skyen ville ødelagt den. Et foreldet stempel
koster en overflødig opplasting; et ferskt koster redigeringen. Tilstanden
observeres nå før senderen leser en eneste byte.

Av samme grunn stempler rammeverket etter *sine egne* punsjinger — utkastelse,
dehydrering og tilbakerullingen i en mislykket hydrering. Punsjing flytter mtime,
og en placeholder som ble stående som `Dirty` ville blitt nektet oppfrisking av
delta-passet *og* lagt i opplastingskø av en resync-vandring — der opplasting
betyr å lese den, og å lese den hydrerer den tilbake.

`Unstamped` er bevisst ikke det samme som `Dirty` for delta-passets del: en fil
rammeverket aldri har skrevet må ikke overskrives. Men for *opplastingsretningen*
er den signalet som mangler, og det tok en gjennomgang å se. De fleste editorer
skriver ved å lage en midlertidig fil og døpe den over målet. En omdøping bytter
inoden, og stempelet ligger på inoden — så erstatningen bærer verken stempel
eller sky-id. Hendelsesstien fanger dem; resync-vandringen, som finnes nettopp
for når hendelsesstien ikke gjorde det, hoppet over den vanligste redigeringsformen
som finnes.

Vandringen tar nå to slag: `Dirty`, og `Unstamped` med innhold og uten sky-id.
Det andre er per definisjon en fil rammeverket aldri har *sendt* — enten fordi
brukeren nettopp laget den, eller fordi en omdøping erstattet en som var sendt.
Det legger ikke hele katalogen i kø, fordi alt rammeverket har plassert, hydrert
eller lastet opp er stemplet. Det henter også opp opplastinger som feilet, som
ingenting annet gjorde.

Kanalen sier fra når den har hull. `FromHelper::Resync` sendes ved køoverløp —
markøren kommer uten deskriptor og ble tidligere kastet sammen med alt annet
fd-løst, altså var det ene signalet som sier «du har mistet endringer» det eneste
som ble stille forkastet. Klienten vandrer da katalogen og sammenligner stempel
mot `stat`. Det samme skjer ved oppstart og hver gang hjelperen kobler til på
nytt, siden begge er tilstander der endringer skjedde som ingen hendelse
noensinne vil nevne.

---

## 6h. Utkastelse trenger ikke den privilegerte siden

Dette var det siste punktet i §8 uten utløser, og grunnen var §6b. En utløser må
navngi en fil, og den privilegerte siden tar aldri imot en destinasjon. Å gi root
en sti å punsje hull i er verre enn å gi den en sti å skrive til — det er
vilkårlig ødeleggelse som root — og å låne ut evnen til å undertrykke hendelser
på en navngitt inode er evnen til å få hvilken som helst fil til å lese som
nuller.

Svaret lå allerede i opprettelsen. En placeholder trenger ikke lages ved å hule
ut filen som er der; den kan bygges på en anonym inode og byttes inn. `place()`
gjør nøyaktig det, uten privilegier — så utkastelse er bare plassering over en
fil som tilfeldigvis har innhold, og den privilegerte halvdelen er ikke involvert
i det hele tatt.

Forskjellen fra å punsje på stedet, og begge er verdt å vite:

- **Inoden byttes.** Den som holder den gamle filen åpen leser videre innholdet
  de åpnet — bedre enn å få det fjernet under seg — og blokkene frigjøres når de
  slipper. Harde lenker til den gamle inoden beholder innholdet, så utkastelse
  frigjør ingenting for dem før siste lenke er borte. Det er det ærlige utfallet,
  siden innholdet fortsatt er tilgjengelig under et annet navn.
- **Ingen ignore-merke må fjernes.** Det gamle merket dør med inoden, og den nye
  har aldri hatt et — så filen avskjæres igjen ved konstruksjon framfor ved et
  privilegert kall som må sekvenseres riktig.

Innelukkingen er strukturell, ikke sjekket, og det tok en gjennomgang å få
riktig. Første versjon tok en absolutt sti og spurte om den *begynte* med roten.
`Path::starts_with` sammenligner komponenter leksikalsk og løser ikke `..` — så
hver eneste stien som rømte begynte med roten og slapp gjennom. `evict
../SECRET.txt` erstattet en fil utenfor synkkatalogen med en placeholder hvis
sky-id ikke løser noe sted, altså den filens innhold ødelagt og lest som nuller
for alltid. Og det er ikke en eksotisk situasjon: en omdøping ut av synktreet
beholder xattr-ene, og en annen synkrot under samme forelder er `../andre/x`.

`safe_join` fantes allerede for nøyaktig dette, på delta-siden, og ble ikke
brukt. Nå tar `reclaim` en relativ sti og går gjennom den — og deretter gjennom
filsystemet, siden en symlenket underkatalog gir en sti som er helt `Normal` og
likevel lander utenfor.

Utløseren ligger i den kjørende daemonen, ikke i verktøyet, og det er poenget:
et frittstående verktøy kunne kastet ut en fil daemonen laster opp akkurat nå, og
regelen om sletting under opplasting (§5.5) ville da sett at inoden byttet og
fjernet objektet den nettopp lagde. Bare prosessen som eier køen kan nekte det.

`hydrationd`s egen `evict` finnes fortsatt, for en kaller som *har* gruppen —
konformansadapteren er en — og punsjer på stedet der.

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
4. **Tidsfrist per hendelse, og en vakt som overvåker fremdrift (§6a-bis).** En hengt
   arbeider kan ikke drepes og låser hele monteringen; det er en annen feil enn en
   død arbeider, og §6a dekker bare den siste.
5. **Privilegieseparasjon med spesifisert protokoll (§6b).** Root-siden ser aldri et token.
6. Placeholder: sparsom fil, riktig størrelse, sky-ID og modus i xattr, `chattr +d`.
7. Hydrering ved `FAN_PRE_ACCESS` — hele filen, ikke områder (se under).
8. `FAN_MARK_IGNORE_SURV` på hydrerte filer, så de koster null.
9. Endringsdeteksjon → debounce → opplasting, med de fem reglene i §5.
10. Dehydrering: `PUNCH_HOLE` + fjern ignore-merke + sett nodump, og en utløser
   brukeren kan kjøre (`hydration-ctl evict <sti>`). Se §6h — utløseren så ut til
   å kreve at den privilegerte siden tok imot en destinasjon, og gjorde det ikke.
11. **Hydreringspolicy (§6c):** pidfd→cgroup, standardliste, `FAN_DENY_ERRNO(EPERM)`,
   synlig nektelseslogg.
12. Konformanstestpakken. Alle åtte invariantene, pluss fail-closed-testen fra §6a.
13. `FAN_DENY_ERRNO(EIO)` ved nedlastingsfeil — aldri stille nuller.

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

## 8a. En lesing forbi EOF utløser en hendelse

Verdt å skrive ned fordi antagelsen om det motsatte er nærliggende og feil.
`probes/emptyread.c`, 6.17:

```
empty (0)      size=0     events=1  read completed
sized (4096)   size=4096  events=1  read completed
```

En lesing av en fil uten byte fyrer altså en pre-content-hendelse, akkurat som en
lesing av en fil med innhold. To konsekvenser:

- **Enhver tom fil i synkkatalogen koster en rundtur** ved første lesing, til
  ignore-merket settes. Uunngåelig, og billig.
- **Tom-fil-regelen i §6a-ter mister ingen kappløp**, men ikke av den grunnen man
  først tror. Den blokkerte leseren finnes. Det som lukker det er at regelen bare
  gjelder inoder uten navn: en placeholder med innhold har `st_size > 0` og
  treffer aldri grenen, og en anonym inode har ikke noe skyobjekt å hente. Det
  finnes altså ingen tilstand der regelen hopper over en hydrering som skulle
  skjedd.

---

## 8b. `BindsTo=` river ned og kommer ikke tilbake

Enhetene ble skrevet med `BindsTo=` fordi det uttrykker kravet presist: en merket
montering må ikke overleve prosessen som svarer på hendelsene dens. Det gjør det
også. Men hjelperen kobler selv fra monteringen på vei ut (§6a-bis), og da leser
systemd den resulterende stoppen som *bevisst* og undertrykker omstarten helt.

Målt med kastbare enheter som speiler paret:

| Avhengighet | Etter at hjelperen kobler fra og avslutter med 75 |
|---|---|
| `BindsTo=` (som levert) | tjeneste inaktiv, montering inaktiv, **0 omstarter** |
| `Requires=` | tjeneste inaktiv, montering inaktiv, **0 omstarter** |
| `Wants=` | tjeneste aktiv, **montering inaktiv** |
| `RequiresMountsFor=` | tjeneste aktiv, montering aktiv, 2 omstarter |

Med `BindsTo=` ville altså enhver uopprettelig tilstand — en fastlåst henter,
en synk-daemon som forsvant — tatt utrullingen permanent ned. `Wants=` starter
tjenesten igjen uten monteringen, som bare gir en omstartsløkke.
`RequiresMountsFor=` gjenoppretter fullt, tre av tre, og beholder
sikkerhetsegenskapen: en administrators `umount` stopper fortsatt tjenesten
(målt).

Forskjellen er usynlig i enhetsfilen og total i praksis, som er grunnen til at
den er skrevet ned framfor bare rettet.

---

## 8c. Delvis fylling er trygt — målt før det ble bygget

Taket på hva rammeverket kan servere er i dag hele objektet i minnet innen én
frist. Å heve det betyr å fylle placeholderen mens bytene kommer, og det skaper
en tilstand som ikke finnes i dag: en placeholder som er *delvis* fylt, fortsatt
merket, med leseren sin parkert inne i pre-content-hendelsen.

Fire spørsmål avgjorde om den tilstanden er trygg. `probes/stream.c`, 6.17,
btrfs:

```
event held for a 1 MiB placeholder
  wrote 262144 of 1048576 bytes so far
  events fired by our own partial writes: 0
  a second reader: BLOCKED (its own event is queued behind ours)
  after rollback: size=1048576 blocks=0
  the reader got an error, as it should
```

- **En annen leser kan ikke se det halvskrevne innholdet.** Hennes egen hendelse
  køes bak den som betjenes. Det var det avgjørende: kunne en tilskuer lest det
  halve, ville streaming latt noen tro på en halv fil, som er nøyaktig utfallet
  rammeverket finnes for å hindre.
- **Egne delskrivinger utløser ingen hendelser**, så fella i §6a-ter dukker ikke
  opp i en niende forkledning her.
- **Tilbakerulling gjenoppretter nøyaktig**: størrelsen beholdt, blokkene tilbake
  til null. §5.7s «hele objektet eller ingenting» holder altså på
  filsystemnivå, ikke bare i bufferlogikken.
- Og leseren får en feil, ikke nuller.

Målt før noe ble bygget, fordi svaret på det første spørsmålet ville avgjort om
streaming i det hele tatt er en mulig vei.

---

## 9. Det jeg ikke fikk verifisert

Det finnes ingen gjentilkobling i prosessen. En klientomstart overlever ved at
paret bygges opp på nytt, ikke ved at forbindelsen repareres.

I ærlighetens navn, siden dette skal være beslutningsgrunnlag:

- ~~Katalogmerker~~ — **lukket.** `probes/dirmark.c` måler alle fire marketyper: et rent
  katalogmerke godtas og leverer ingenting, `FAN_EVENT_ON_CHILD` dekker bare direkte barn.
  Eget monteringspunkt er dermed et krav (§6.4).
- ~~Bind-mount~~ — **lukket, og svaret ble strengere enn spørsmålet.** Verken bind til en
  egen sti eller bind over seg selv holder; begge har en omvei som leverer nuller (§6.4a).
  Kravet er at ingen annen montering eksponerer filene, og det kan vi ikke håndheve — bare
  oppdage, med `FAN_MNT_ATTACH`. Jeg har **ikke** kjørt en probe på selve
  `FAN_MNT_ATTACH`-abonnementet isolert, men eksponeringsvakten som bygger på det
  har fire tester som kjører mot en ekte montering (`tests/exposure.rs`).
- ~~`FAN_MARK_IGNORE_SURV`~~ — **lukket.** `probes/ignoremark.c`: godtatt, undertrykker,
  og overlever endring. Ytelsespåstanden står.
- ~~mmap- og `truncate`-hydrering~~ — **lukket, og begge svarene var de gode.**
  `probes/mmapread.c`, 6.17: en *mappet* lesing av en placeholder utløser én hendelse og
  leseren får hydrert innhold. Det var det farligste åpne punktet her — de fleste
  språkruntimer, databaser og enhver ELF-laster mapper framfor å lese, og en udekket
  mmap ville gitt dem hullet uten feilmelding. `truncate` fyrer også, og det som
  overlever en forkorting er det ekte innholdet, ikke nuller. Udekket ville en
  forkortet placeholder blitt til de første N *nullene* — verre enn nuller, fordi
  resultatet ser ut som en bevisst redigering og ville blitt lastet opp.
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
