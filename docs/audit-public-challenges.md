# Audit against public CTF forensics challenges (2026-11-11)

Troisième audit : cette fois contre des challenges **publics** et leurs solutions
connues, en faisant tourner l'outil sur les vrais fichiers (pas en lisant les
write-ups). Objectif : mesurer « est-ce que ctfc aurait sorti le flag en collant
l'artefact, sans LLM », et noter chaque échec pour améliorer l'outil ensuite.

Les fichiers ont été téléchargés dans `corpus/` (gitignored, jamais commité :
ce sont des samples non vérifiés). Sources : HTB Cyber Apocalypse 2024, DownUnderCTF
2021-2024, picoCTF (picoGym). Les flags eux-mêmes ne sont **pas** reproduits ici
(règle §9 : on ne commite jamais de vrai flag) : seuls les mécanismes le sont.

La méthode, le détail par challenge et les flags vérifiés sont dans
`corpus/notes.md` (local, non commité). Ce document garde ce qui sert la suite :
le score, les **bugs trouvés et corrigés**, et le **backlog priorisé**.

## Comment refaire cet audit

Les challenges viennent de dépôts publics (CyBench a les releases HTB avec les
réponses ; DownUnderCTF et les write-ups picoCTF de Rubix982/SecChapter ont les
fichiers d'origine). Le harnais : `corpus/` tient `challenges/<ctf>/<nom>/` et
`answers/`, un script lance `ctfc solve` sur chaque fichier et `ctfc workspace`
sur chaque dossier multi-fichiers, en JSON, et on compare aux flags attendus
extraits des réponses. Vérité terrain de chaque fix : un outil externe (tshark
pour les pcap, samdump2/secretsdump pour SAM, pngcheck pour PNG, pycryptodome
pour MD4).

## Score (34 challenges représentatifs)

| Issue | N | Ce que ça veut dire |
|---|---|---|
| **Résolu, une commande** | 11 | `ctfc solve` sort le flag seul (eml, exif, LSB, pcap, hex/base64…) |
| **Résolu, ctfc fait la crypto + colle à la main** | 5 | ctfc trouve clés/mots de passe et déchiffre ; quelques étapes de plomberie manuelles |
| **Partiel** | 4 | ctfc va loin mais une brique manque (un KDF, un reader, une recherche) |
| **Échec — visuel/OCR** | 4 | le flag est dessiné dans des pixels : hors scope (pas de ML) |
| **Échec — feature manquante** | 9 | fonctionnalité identifiée et chiffrée, à construire |
| **N/A — service en ligne** | 1 | le flag vient d'un service vivant |

Autrement dit : **16/34 sortent un flag** (dont 5 grâce à des correctifs de cet
audit), 4 autres s'arrêtent à une étape d'OCR qu'on ne fera pas, et le reste
trace un backlog clair.

## Bugs trouvés et corrigés pendant l'audit

Tous avec un test et validés contre un outil externe.

1. **pcap : le padding Ethernet lu comme payload** (`4616f70`). Un ACK vide est
   bourré de zéros jusqu'au minimum Ethernet (60 octets) ; la longueur totale IP
   n'était pas appliquée, donc ces zéros devenaient 6 octets de payload TCP, au
   même numéro de séquence que le segment suivant — l'en-tête d'une réponse HTTP
   ressortait en 388 zéros. Corrigé : on coupe à la longueur IP (v4 total length,
   v6 payload length) et, de deux segments au même offset, on garde le plus long.
   **91/91 directions de flux identiques à tshark** après coup (HTB « Fake Boost »).

2. **pcap : link types raw-IP 228/229 ignorés** (`4616f70`). `LINKTYPE_IPV4`/`IPV6`
   (ce que scapy écrit) et DLT_RAW 12/14 n'étaient pas reconnus : tous les paquets
   d'une capture étaient jetés (picoCTF « PcapPoisoning »).

3. **pcap : deux connexions au même serveur partageaient un nom de fichier**
   (`79bc53a`). Chaque extracteur numérote ses objets dans un seul flux, donc deux
   réponses HTTP du même serveur étaient toutes deux `http_<serveur>_0.bin` ;
   `--extract` écrasait la première (le PowerShell du challenge) par la seconde.

4. **sym : une clé RC4 de longueur inhabituelle n'était pas essayée telle quelle**
   (`346260d`… en fait le commit RC4). RC4 accepte 1 à 256 octets, mais le
   générateur ne testait que 16/32/8/5 : une clé de 20 caractères était
   redimensionnée et ne déchiffrait jamais rien (HTB « Game Invitation », la clé
   est l'argument de ligne de commande de la macro).

5. **hashes : NTLM incraquable sans MD4 dans OpenSSL** (`346260d`). NTLM = MD4 de
   l'UTF-16LE du mot de passe, le hash de tout dump SAM ; OpenSSL moderne retire
   MD4, donc ctfc savait nommer un NTLM mais jamais le craquer. Ajout d'un MD4 en
   Python pur (`core/md4.py`, RFC 1320, vérifié contre pycryptodome). Le test qui
   skippait tourne maintenant (DUCTF « samiam » : SAM → NTLM Administrator → rockyou).

6. **solve : une APK meurait sur le DEX au lieu de marcher comme un ZIP**
   (`ef668fd`). Le reader exe revendiquait l'APK (un ZIP de ressources + classes.dex)
   et refusait. Une APK se promène maintenant comme un ZIP (le flag y est souvent
   dans `res/`, `assets/` ou le manifeste) ; un .dex brut, un ELF, un .class, un
   .jar sont inchangés.

## Lot I — construit juste après l'audit (2026-11-11)

Le rang 1 du backlog ci-dessous (sauf les préfixes connus : décision de
l'utilisateur, l'outil sert à CYBN, on garde `CYBN{` en clair et en base64).
Vérifié sur les vrais fichiers du corpus :

| Challenge | Avant | Après lot I |
|---|---|---|
| CanYouSee | rien | **flag, une commande** (base64 dans l'XMP, décodé) |
| Thats_Not_My_Name | rien (objet n° 1240 sur 6436) | **flag en 12 s** (flux DNS déhexé, tunnel trié en tête) |
| It Has Begun | rien | **flag recollé** de deux moitiés (inversée + base64) |
| Fake Boost | **faux flag** `K4J{...}` | plus de faux flag ; moitié 1 sortie comme fragment (la 2 est en AES) |
| badpolicies | sortie UTF-16 non reconnue | UTF-16 reconnu ; manque la clé GPP publique |

Score : **19/34** (contre 16). Détail : `ctfc/data/how-it-works.md` §43.

## Backlog priorisé (ce que l'audit dit de construire ensuite)

Classé par rapport valeur/effort, chacun relié à des challenges réels.

### Rang 1 — cheap, débloque plusieurs challenges
- **Chercher le flag dans les octets décodés / les chaînes des médias.** Plusieurs
  challenges laissent le flag en base64 dans une métadonnée (segment XMP d'un JPEG),
  ou en clair dans un flux d'exfiltration DNS déjà déhexé par ctfc, et `solve`
  s'arrête juste avant. `auto`/`search_flags` sur chaque chaîne imprimable ≥ 8
  d'un média, et sur la sortie déhexée des objets dns-exfil. (CanYouSee, Thats_Not_My_Name)
- **Fragments de flag.** `PREFIX{` sans fin, `…}` sans début, `}…{BTH` inversé :
  les signaler comme « morceau de flag » plutôt que rien. (It Has Begun, Fake Boost)
- **Préfixes de flag connus intégrés** (HTB, picoCTF, DUCTF, flag, CTF…) pour la
  chasse encodée (base64 aux 3 alignements, hex, inversé), en plus de ceux du config.
- **`reverse` dans auto pour tout long texte en charset base64**, pas seulement
  quand ça commence par `=`. (Fake Boost stage 1)
- **Recherche de flag en UTF-16LE** sur les sorties (badpolicies, part 3 de Data Siege).

### Rang 2 — un reader / un KDF, valeur forte en forensics
- **KDF « Rfc2898 » (.NET) :** PBKDF2-SHA1/1000 (aussi 10000, sha256) dérivant
  key‖IV d'un seul coup ; et essayer les courtes chaînes ASCII d'un binaire comme
  sels. (Data Siege : tous les ingrédients sont trouvés, seule la recette manque)
- **Reader SAM/SYSTEM** (déchiffrement des hash NT via bootkey). secretsdump.py et
  samdump2 sont installés ici → vérité terrain disponible. Transformerait samiam
  en un seul coller-coller. (samiam)
- **Morse audio** (Goertzel sur quelques fréquences, stdlib) → table Morse existante.
  Deux challenges sur 36. (do_the_loop, blinky-bill)
- **Reader MFT** ($MFT NTFS : noms, parents, dates $SI/$FN, flags, $DATA résident)
  → alimente timeline. Vérité terrain : analyzeMFT / MFTECmd. (Persue The Tracks)
- **Décodeur dnscat2** (labels hex → id/type/session/seq/ack/data, dédoublé par seq)
  et classement des objets dns-exfil par nombre de requêtes / entropie des labels,
  pour que le domaine d'exfil passe devant le bruit CDN. (Thats_Not_My_Name)

### Rang 3 — plomberie qui paie
- **workspace/solve : lire les petits fichiers d'abord**, le gros binaire en
  dernier ; et faire tourner le produit croisé workspace sur les pièces d'une
  seule capture (mot de passe et zip sont dans le même pcap). (Phreaky)
- **Priorité des enfants d'un conteneur** : un fichier nommé *flag*, un petit texte,
  un court blob hex/base64 doivent passer avant les assets en vrac quand un conteneur
  dépasse le plafond de 120 enfants. (Mob psycho, member #222)
- **Détecter une série `nom.partN` / `.001 .002`** parmi les pièces et les
  recoller dans l'ordre numérique. (Phreaky : 15 parts d'un PDF)
- **Réparation PNG : longueur de chunk corrompue.** `read_chunks` casse sur le
  premier chunk dont la longueur dépasse le fichier, perd l'IDAT et tout ce qui
  suit, puis affiche « no IDAT chunk » (faux). Resynchroniser sur la frontière de
  chunk suivante et proposer une longueur corrigée. (c0rrupt)
- **Timeline : lire les dates dans le texte des logs** (syslog `[YYYY-MM-DD …]`,
  ISO 8601, bash_history `#<epoch>`). (An unusual sighting)
- **Bridge outils WPA** : extraire l'EAPOL d'un handshake et sortir la commande
  hashcat/aircrack (hccapx). (WPA-ingOut)
- **Fichier keylog TLS** : le détecter (lignes CLIENT_RANDOM / *_TRAFFIC_SECRET_0)
  et imprimer les commandes tshark exactes (`-o tls.keylog_file:…`). (emuc2)

### Hors scope confirmé (pas de ML)
Flag dessiné dans des pixels (doxme, extensions, hideme interne) et QR en travers
de frames GIF (how-to-pronounce-gif). ctfc va jusqu'à l'image et s'arrête ; il
suggère déjà zbarimg via `ctfc tools`. Un extracteur de frames GIF et un bridge
zbarimg sont le maximum possible sans OCR.

## Ce qui a bien marché (à ne pas casser)

- `ctfc workspace` sur les 15 mails de Phreaky : **15/15** mots de passe appariés
  à leur zip, chacun avec la commande `unzip -P`. C'est exactement ce pour quoi
  le workspace existe.
- Le **solveur symmetric sans paramètres** : base64 du ciphertext, clé en base64,
  IV préfixé, KDF openssl — tout détecté seul sur des payloads réels (Fake Boost,
  cpassword GPP).
- `ctfc pe` lit les littéraux .NET #US → la clé du RAT de Data Siege est en clair.
- `ctfc hive` sur un SAM s'arrête **honnêtement** et pointe samdump2/secretsdump
  au lieu d'inventer un déchiffrement non vérifié.
- La **chaîne de carving de solve** (PNG → ZIP appended → PNG interne) marche de
  bout en bout ; seul l'OCR final manque.

## Deuxième audit public (2026-11-12) — lot J

Trois CTF de plus, uniquement forensics, lancés en aveugle avec `ctfc solve` sur
les vrais fichiers : **ImaginaryCTF 2024, BuckeyeCTF 2023/24, DownUnderCTF 2020**
(22 challenges). Fichiers dans `corpus/challenges/` (gitignorés) ; harnais
`scratchpad/harness.py` (non commité). Cinq readers manquants construits, chacun
avec une vérité terrain externe (voir `ctfc/data/how-it-works.md` §44) :

| Reader | Débloque | Vérité terrain |
|---|---|---|
| GPP `cpassword` (`core/gpp.py`) | badpolicies (DUCTF 2024) | vecteur public GPP + flag réel |
| flux gzip/bzip2/xz (`compressed`) | unknown (Buckeye 2024) | gzip/bz2/lzma stdlib |
| capture InfoVista 5View | sneaky (DUCTF 2020) | `editcap -F pcap` : 499/499 trames |
| nom DNS en texte littéral | sneaky | la trame scapy forgée |
| frappe USB appui/maintien + Ctrl-⌫ | duck-pics (Buckeye 2024) | tshark `usbhid.data` : 10950/10950 |
| `ctfc zip --wordlist` | sneaky (zip) | zip chiffré par Info-ZIP `zip -P` |

**Ce qui reste hors scope** (pas de ML, pas de crackers externes intégrés) :
SSTV audio (couch_potato), spectrogramme (On-the-spectrum), image dans un core
dump (wreck → binwalk), PDF/zip à casser par hashcat (the_cia, reduce_recycle),
NBTExplorer (playful-puppy), mkbootimg (replace-me), steghide (i-love-scomo,
SpotTheDifference). `ctfc` va jusqu'au fichier et nomme l'outil.

## Troisième audit public (2026-11-12) — lot K

Deux CTF de plus, uniquement forensics : **IrisCTF 2024** (forensics + réseau) et
**ImaginaryCTF 2023**. Dépôts qui livrent les fichiers (dossier `dist/` par
challenge). Harnais auto-découvrant (`scratchpad/audit.py` : repère les fichiers
distribués, scrape les flags attendus, lance `ctfc solve`). Beaucoup de ces
challenges sont hors scope (puzzle de police MKV, géoloc OSINT, DSSS, SSTV,
image-dans-les-pixels). Les gains nets, chacun avec vérité terrain :

| Feature | Débloque | Vérité terrain |
|---|---|---|
| **802.11 WiFi** (`core/wifi.py`) : trames ouvertes → IP, handshake WPA → hashcat | copper-selachimorpha, skats-network-history (IrisCTF) | tshark (SSID, EAPOL) |
| **keylog TLS** (`keylog` reader) : reconnaît `sslkeyfile`, sort la commande tshark | skats-network-history | format NSS |
| **récupération pcap** : magic + `captured_len` écrasés, rejoués via `orig_len` | forensics (ImaginaryCTF) | capture propre = octet à octet |

Note : les deux challenges WiFi restent à cracker (clé WPA, hors scope) ; ctfc
va désormais jusqu'au handshake + la commande hashcat exacte. La capture
corrompue est reconstruite à l'identique ; le flag final est ensuite dans une
image transférée (analyse d'image, hors scope).


### WaniCTF 2024 (via le miroir sajjadium/ctf-archives)

Le miroir livre les handouts mais pas les flags, donc jugé à l'oeil. 6 forensics :
**tiny_usb** = une **ISO 9660** -> nouveau reader `core/iso.py` (vérité terrain 7z),
qui extrait `FLAG.PNG` (le flag y est dessiné : visuel, hors scope ensuite).
Les autres sont hors scope : codebreaker (QR, zbarimg suggéré), tiny_10px (image
agrandie), I_wanna_be_a_streamer (flux RTP vidéo), Surveillance_of_sus (cache
bitmap RDP `RDP8bmp` à reconstruire, bmc-tools). Seul l'ISO était dans le périmètre
sans OCR ; il est maintenant lu.

## Quatrième audit public (2026-11-12) — DEADFACE + TJCTF

Via le miroir `sajjadium/ctf-archives` (livre les handouts, pas les flags).

**DEADFACE 2024 (net)** : **Data_Breach** et **Wild_Wild_West** sortent le flag
seuls (fuite dans un en-tête HTTP, Kerberos kerbrute). Les autres challenges
DEADFACE sont du Q/R d'investigation (le flag est une réponse à déduire, pas une
chaîne dans le fichier) — ctfc remonte les preuves mais ne peut pas auto-flagger.
Bug trouvé et corrigé : un flag à corps fort (`flag{kerbrute_finding_users}`)
noyé dans du binaire était rétrogradé en piste tandis qu'un doublon préfixé par
la realm (`LOCALflag{...}`) gagnait — la rétrogradation « entouré de binaire »
ne s'applique plus qu'aux corps faibles (court, sans underscore).

**TJCTF 2024 (forensic)** : **conversations** (`.pcap.xz`) sort le flag via la
chaîne xz→pcap. **thatsmyjam** (image **ext4** de 199 Mo en `.img.gz`) : le flag
était à 64 Mo, au-delà du plafond de décompression de 8 Mo — relevé à 512 Mo, le
disque est décompressé en entier et le flag trouvé sans reader de système de
fichiers. Restent hors scope : minisculest (PNG aux dimensions truquées, flag
visuel), pals (visuel), purified (image QOI).

Capacité majeure encore absente, repérée ici : un **reader ext4/FAT** (image
disque), gros module mais très courant — 7z/`debugfs` seraient la vérité terrain.

## Lot L — reader d'image disque (2026-11-12)

Construit à la demande : un **reader d'image disque complet**, en pilotant **The
Sleuth Kit** (déjà installé) — `core/disk.py`. Couvre ext2/3/4, FAT, exFAT, NTFS,
HFS+, UFS, et les tables de partitions MBR/GPT ; **récupère les fichiers
supprimés** (`icat -r`). Appels en liste d'arguments (pas de shell), bornés par
nombre de fichiers / taille / temps ; priorité aux chemins intéressants
(home, /tmp, flag) ; fallback sur la recherche brute si TSK absent. Intégré :
commande `ctfc disk`, reader (donc `solve`), onglet Files du web. Vérité terrain :
TSK lui-même + fixture FAT12 vérifiée contre `fls`, y compris un fichier supprimé
et une image partitionnée (MBR). thatsmyjam (ext4 199 Mo) : `ctfc solve` sort le
flag. 1792 tests, démo 77.

### Cinquième audit (corCTF 2024, BackdoorCTF 2024)

Surtout de l'investigation Q/R (le flag est une réponse à déduire, pas une chaîne
dans un fichier) : corCTF infiltration (evtx — ctfc remonte le record avec le
mot de passe), American_Spy (trafic chiffré), Cursed_Credential (profil Firefox :
déchiffrement NSS key4.db/logins.json — capacité niche possible). ctfc remonte
les preuves (records evtx, streams, secrets) mais ne peut pas auto-flagger ces
challenges d'enquête. Pas de nouveau bug : les features actuelles tiennent.

## Sixième audit — 10 CTF en lot (2026-11-12)

Harnais v2 (`scratchpad/audit2.py`) sur **51 challenges forensics** de 10 CTF du
miroir sajjadium (BITSCTF, BYUCTF, 1337UP, Akasec, BCACTF, 0xL4ugh, BSidesSF,
Bearcat, AirOverflow, BTCTF). Le miroir ne fournit pas les flags : on juge par
« ctfc a sorti un flag fort ».

**Vrais flags sortis seuls** : BSidesSF javai (`CTF{javai_java_with_100x_ai}`),
sgai_1 (`CTF{i_name_thee_flag}`), Bearcat Needle (`BCCTF{ThisIsANeedle}`), BTCTF
no_end_in_sight (`btctf{...}`), BSidesSF undelete (chaîne complète xz→tar→**disk
→flag.png supprimé récupéré**→stego ; flag final visuel).

**Deux corrections issues de l'audit :**
- **ztxt** (BSidesSF) : un flag dans un chunk PNG **zTXt** d'un PNG 4 bits était
  perdu car le chargeur de pixels abandonnait avant de lire les chunks texte.
  Les chunks texte sont maintenant lus indépendamment du format de pixels.
- **Faux positifs** : le brute-force sur du binaire (XOR d'un flux PDF, canal
  covert R/Q) produisait des `xx{...}` à corps sans voyelles (`CL{CmvGTKDTDvh2g}`,
  `SSSQ…{PYXS…}`) déclarés flags forts. Un corps générique sans voyelle (ni leet)
  est désormais une piste, pas un flag ; les vrais flags (voyelles/underscore/hash)
  restent forts.

**La limite, mesurée** : une grande part des challenges forensics de CTF est du
**stego visuel, de l'audio, de l'OSINT ou de l'investigation Q/R** (le flag est
dessiné dans des pixels, caché dans un son, ou une réponse à déduire) — hors
périmètre sans OCR/ML. ctfc résout ce qui est « flag dans un fichier / encodé /
réseau / archive / disque / chunk » et remonte les preuves pour le reste.

## Septième audit — les « pistes » quand il n'y a pas de flag (lot M, 2026-11-12)

Nouvelle fonctionnalité : quand `ctfc solve` ne trouve pas de flag, il finit par
**Next steps** — ce qu'il a trouvé, ce que ça veut dire en CTF, les commandes ctfc
puis les **outils externes avec la commande déjà remplie** (installé ou non, et
comment l'installer). Table de règles : `ctfc/data/leads.toml`, moteur :
`ctfc/core/nextsteps.py`, doc : `how-it-works.md` §50.

Mesuré sur les **62 fichiers** du corpus (`corpus/challenges/`, 10 CTF), relancés
quatre fois au fil des corrections. Harnais : `scratchpad/steps.py` (une ligne par
fichier : le flag, ou les règles qui ont tiré).

### Flags sortis seuls : 15 → 17 (+ une moitié de flag)

| Challenge | Avant | Maintenant | Cause |
|---|---|---|---|
| DUCTF 2021 Thats_Not_My_Name | rien | `DUCTF{c4t_g07_y0ur_n4m3}` (15 s) | le pcapng de 69 Mo dans le 7z était **jeté en silence** (plafond 8 Mo des pièces) ; et `hunt` passait 8 s en UTF-16 sur 69 Mo |
| picoCTF Mob psycho | budget brûlé (61 s) | `picoCTF{ax8mC0RU6ve_…}` (0,8 s) | la récupération par CRC32 tournait sur les 772 membres **non chiffrés** de l'APK ; puis `res/color/flag.txt` était au-delà du plafond de 120 pièces |
| HTB Fake Boost | rien | 1re moitié `HTB{fr33_N17r0G3n_3xp053d!_` | même plafond 8 Mo (pcapng de 22 Mo dans le ZIP) |

### Les pistes, jugées contre la vraie solution (fichiers sans flag)

**La piste mène à la solution** (l'outil nommé est celui des writeups) :

| Challenge | Piste n°1 | Vérifié en lançant la commande affichée |
|---|---|---|
| picoCTF WPA-ingOut | aircrack-ng -w rockyou | **oui** : `KEY FOUND! [ mickeymouse ]` = le flag |
| DUCTF i-love-scomo | steghide '' puis stegseek rockyou | **oui** : stegseek extrait le texte ; ctfc sur ce texte → règle `whitespace` → stegsnow (2e couche) |
| DUCTF on-the-spectrum | sox spectrogram | **oui** : le motif est visible (commande agrandie à 2000×1000 après ce test, l'image par défaut était trop petite) |
| DUCTF do_the_loop, blinky-bill | multimon-ng Morse + spectrogramme | multimon-ng décode mal sur fond musical ; la note le dit et renvoie au spectrogramme |
| Buckeye couch_potato | audio → sstv / qsstv | (SSTV, 3e outil de la carte) |
| DUCTF samiam | secretsdump.py -sam … -system SYSTEM | règle `windows.sam` (le faux flag `F2B3AF0D{…}` qui la masquait est corrigé) |
| DUCTF emuc2 | keylog → tshark -o tls.keylog_file ; pcap → TLS | oui (les deux fichiers ont chacun leur piste) |
| Buckeye the_cia, reduce_recycle ×2, picoCTF FindAndOpen/flag.zip, HTB Phreaky | fichier protégé → workspace, zip2john/bkcrack, pdf2john | oui |
| picoCTF endianness-v2 | JPEG remis dans l'ordre (nouveau : `repair` détecte les mots de 2/4/8 octets inversés) → « regarde l'image » | oui (flag dessiné) |
| DUCTF how-to-pronounce-gif | frames ImageMagick/ffmpeg + zbarimg | oui |
| picoCTF Scan Surprise | zbarimg (QR) | oui |
| picoCTF c0rrupt, DUCTF spot-the-difference | `ctfc repair` + pngcheck | oui |
| picoCTF hideme, iCTF elf-sunset | zsteg / stegsolve | oui |
| picoCTF Secret Of The Polyglot | image **et** PDF (nouveau : magic PNG même si lu comme PDF) | oui |
| DUCTF doxme, picoCTF extensions | image → « regarde-la » | oui (flag dessiné) |
| Buckeye wreck | core ELF → strings/binwalk (nouveau `kind:core`) | oui (image dans le core dump) |
| Buckeye replace-me | image de boot Android (nouveau magic `ANDROID!`) → unpack_bootimg | oui |
| Buckeye hall-effect, duck-pics | capture USB | oui |
| HTB Persue The Tracks | `$MFT` (nouveau magic) → MFTECmd / analyzeMFT | oui (Q/R) |
| DUCTF macromagic, HTB Game Invitation | document Office → olevba | oui |
| HTB Data Siege | exécutable → ILSpy/dnSpy (.NET) | oui |
| iCTF sleepy-alarm | MP3 sans tag ID3 → audio (avant : « blob chiffré ») | plausible |

**Piste générique (correcte mais pas décisive)** : babys-first-forensics et An
unusual sighting (Q/R sur une capture / des logs), playful-puppy (fichier Minecraft
`.mca` → « inconnu », il faut NBTExplorer), routed/packed (`.pkt` Packet Tracer
chiffré → « blob chiffré », il faut pka2xml), breaking-away, just-hang-man, dog-mom.

### Bugs trouvés et corrigés pendant cet audit

1. **Pièces > 8 Mo jetées sans un mot** par tous les readers → plafond 256 Mo et une
   note pour ce qui dépasse.
2. **Plafond de 120 pièces appliqué dans l'ordre du ZIP** → les noms prometteurs
   (flag, secret, key, .txt…) passent d'abord, et une note dit combien sont écartées.
3. **Récupération CRC32 sur les membres non chiffrés** (une minute sur un APK) →
   uniquement sur les membres chiffrés.
4. **`ctfc zip --wordlist` plantait** au premier mauvais mot de passe qui passe le
   contrôle d'un octet de ZipCrypto (1 sur 256 : `zlib.error`), donc dès les premières
   centaines de mots de rockyou.
5. **`hunt` UTF-16 lent** sur les gros fichiers (4,5 s sur 69 Mo) → au-delà de 8 Mo,
   seulement autour des accolades UTF-16 (0,5 s).
6. **« Chiffre classique » sur du texte en clair** (README, logs sshd, HTML, VBA) →
   garde-fou par taux de bigrammes courants (texte ≥ 0,36 ; rail fence 0,28 ;
   substitution < 0,1), et `flag_shift` non-César affaibli dans un texte en clair.
7. **Faux flag `F2B3AF0D{…}`** (valeur hex dans une hive SAM) → un préfixe purement
   hexadécimal avec chiffres n'est pas un nom de CTF.
8. Commandes affichées **non quotées** (`steghide … -p  -f` : `-f` devenait la
   passphrase au copier-coller) → `shlex.join`.
9. `ctfc tools --list` exigeait un fichier d'entrée.

### Ce qui reste (backlog de cet audit)

- `.mca` (Minecraft, NBT) et `.pkt` (Packet Tracer) : signatures + règle, le jour où
  un challenge le justifie.
- Décoder SNOW soi-même (stegsnow n'est pas installé ici : pas de vérité terrain).
- Quelques faux « classical » restent sur des requêtes HTTP très courtes (bruit, pas de
  blocage).

## Huitième audit — 7 nouveaux CTF (lot N, 2026-11-13)

22 challenges forensics de **7 CTF** jamais vus (AuvergnHack 2025, BuckeyeCTF 2025,
CrewCTF 2024, GreyCat 2025, HeroCTF 2024/2025, IrisCTF 2025), via sajjadium +
les dépôts publics. Harnais : `scratchpad/steps.py` (une ligne par fichier).

### Flags sortis seuls

| Challenge | Flag | Comment |
|---|---|---|
| BuckeyeCTF 1985 | `bctf{D1d_y0u_Us3_An_3mul4t0r_Or_d3c0mp1lEr}` | uu → xor('*'), déjà couvert |
| BuckeyeCTF The_Professors_Files | `bctf{docx_is_zip}` | flag dans `theme1.xml` du docx |
| IrisCTF deldeldel | `irisctf{this_keylogger_is_too_hard_to_use}` | HID USB dans un pcapng |
| **BuckeyeCTF zip2john2zip** | `bctf{not_all_hashes_are_hashed_equally}` | **nouveau (lot N)** : le `$pkzip2$` porte les octets chiffrés, ctfc casse et déchiffre le fichier depuis la ligne elle-même |

### La nouveauté : les lignes `$pkzip2$` (zip2john)

`zip2john` ne hache rien pour ZipCrypto : il **recopie les octets chiffrés** dans
la ligne, avec le CRC-32 du clair. Donc le bon mot de passe déchiffre le fichier
*depuis le hash*, l'archive n'est même pas nécessaire (challenge « zip2john2zip » :
on n'a que le hash). Construit :

- `core/zipcrypto.py` : le stream PKWARE traditionnel (CRC-32 brut, pas
  `zlib.crc32` qui inverse), vérifié octet pour octet contre `zipfile`.
- `core/pkzip2.py` : lit la ligne (`$pkzip2$C*B*DT*...`), essaie les mots de passe
  (filtre 12 octets d'en-tête puis CRC-32, ~100 000/s), déchiffre et **reconstruit
  le ZIP** (ouvert par 7z et `zipfile` avec le mot de passe, et refusé sans).
- `ctfc hash <fichier> --wordlist rockyou --out flag.txt` : accepte un fichier,
  sort le flag et écrit le fichier. Mode hashcat déduit (17200/17210/17220/17225).
- Reader `pkzip2` + piste `zip2john` (le mot de passe `factfinder` du challenge
  est à la ligne 955 100 de rockyou → ~9 s dans ctfc, ou hashcat).
- **Vérité terrain** : `hashcat -m 17210` casse la même ligne ; 7z ouvre le ZIP
  reconstruit. Test `test_audit8.py` (skip si 7z/hashcat absents).

### Bugs trouvés et corrigés

1. **Faux flag de force 1,0 depuis un reader** : `0x{2:X8}` (une chaîne de format
   .NET dans un log PowerShell, HeroCTF Operation Pensieve) était déclaré flag par
   le reader evtx et stoppait la recherche. `solve` re-note maintenant tout flag
   rendu par un reader avec `flags.rate()` : un `XXX{...}` générique faible n'est
   plus gardé comme la réponse.
2. **`repair.byte_order` bouclait en Python sur un fichier entier** : le JSON de
   227 Mo d'IrisCTF Tracem_1 faisait un **timeout > 300 s**. `swap_words` utilise
   `array.byteswap` (C) et ne retourne tout le fichier que si l'en-tête inversé
   montre déjà une signature. 300 s → 20 s.
3. **Regex de flag générique quadratique** : sur une sortie binaire avec beaucoup
   de `{`, sans `}` ni `\n`, le corps `[^}\n]{4,}` partait en O(n²) (8 s sur
   400 Ko d'un essai XOR). Borné à `{4,120}` (un corps > 120 n'est jamais gardé).
   CSV HeroCTF Tenant_trouble : 20 s → 5,7 s.
4. **`ctfc zip --wordlist` mentait sur du WinZip AES** : `zipfile` n'ouvre que
   ZipCrypto, donc chaque mot « échouait » et l'outil disait « aucun n'est le mot
   de passe » (CrewCTF Fiilllleeeeeeee, dont le mot de passe était dans la liste).
   Il dit maintenant que la liste n'a PAS été essayée et renvoie vers zip2john/hashcat.
5. **Faux carve `.vmdk`** : le magic VMDK ne fait que 4 octets (`KDMV`) et
   apparaît par hasard à 185 Mo dans le JSON de Tracem_1 → un faux disque de 42 Mo
   mâché par The Sleuth Kit. Le sig épingle maintenant la version (1/2/3) du
   sparse header : 8 octets, plus de hasard.

### Jugé mais hors scope (pas de ML, investigation Q/R)

- **AuvergnHack StratoMonk 1/2** : captures d'appels système **sysdig (.scap)**.
  Flag = IP + chemin + commande à reconstruire. Tentative d'ajout d'un magic .scap
  **abandonnée** : le BOM pcapng `0x1A2B3C4D` écrit en little-endian **est**
  `4d3c2b1a`, donc ma signature se déclenchait sur tout pcapng LE — et le sysdig
  installé ici ne lit même pas ce `.scap` (pas de vérité terrain). `strings` montre
  déjà `ps -p 1;nc 192.168.1.99 8000 -e sh` et les chemins cron.
- HeroCTF Operation Pensieve (DCSync), Tenant_trouble (logs de connexion Azure),
  IrisCTF Tracem_1 (227 Mo d'EDR), StratoMonk : **investigation Q/R**, le flag est
  une réponse à déduire, pas un fichier à déchiffrer.
- Beezchurger (GIF), shredder (PNG déchiqueté à reconstruire d'après le `.c`),
  Bugle (MP3, spectrogramme), Layer_Cake / Notsus.Exe (zips imbriqués chiffrés),
  Recursion / Unfare (USB/NFC), RIP_Art (pcap) : stego visuel, audio ou multi-étapes.

**Tests** : 1859 passent (+13), `make fuzz` propre (32 000 tours / 40 readers),
`make fuzz-web` propre (52 routes).
