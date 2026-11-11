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
