# Malware analysis report: bot_linux_x86_64 (ToxNetV2 bot)

**Analyst:** Kimi (automated malware-analysis skill)  **Date:** 2026-07-28  **Classification:** TLP:AMBER

## Determination

**Verdict:** Malicious
**Confidence:** High
**Family:** ToxNetV2 — a Mirai-style distributed denial-of-service (DDoS) botnet using the Tox peer-to-peer (P2P) protocol for command and control (C2). Basis: the binary embeds toxcore 0.2.22, a systemd unit literally named "Toxnet Bot", the exact attack-vector names, exploit payloads, and `kaf.sh` downloader URL documented in the public [ToxNetV2 framework source](https://github.com/Sewer2K/ToxNetV2).

The sample is a DDoS bot that takes attack, scanning, and destructive commands over the encrypted Tox P2P network, self-replicates onto vulnerable routers, and can brick the infected host on command.

## Executive summary

This file is a Linux botnet agent. Once run, it hides as a kernel thread, installs itself to survive reboots (systemd, cron, rc.local), and connects to the Tox encrypted chat network to receive orders. On command it launches any of 18 DDoS attack types against a victim, scans the internet for vulnerable routers (GPON, Netgear, D-Link, HNAP, TR-064, and others) and infects them with copies of itself, kills competing malware, locks down the host's network, or deliberately destroys the infected machine by wiping the filesystem and forcing a reboot. Treat any host that executed it as fully compromised; rebuild it and check neighboring devices, especially routers.

## Sample metadata

| Field | Value |
| --- | --- |
| File name | `bot_linux_x86_64` |
| File type | ELF 64-bit LSB executable, x86-64, statically linked, stripped |
| Size | 1,624,304 bytes |
| MD5 | 868846ceba7491c7e37b48dd08688b38 |
| SHA-1 | ef14353452fee94bccceb6d24f47480e9b2863a8 |
| SHA-256 | 0a70e73d780b9beed234b0376b0136e39f09d1961c08c8505cad5849ff51a562 |
| Build ID | 72ebf2df27dbc162a86e2bd1620cd907ea8f4238 |
| Compile timestamp | None in ELF headers; `.comment` shows GCC 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) |
| Signature | Not applicable (ELF, unsigned) |
| Entry point | 0x401cc0 (ET_EXEC, non-PIE) |

## Analysis stages

### Stage 1 — the full bot (only stage)

The binary is not packed and contains no secondary stage. Overall entropy is 6.42/8.0 and every malicious string is plaintext in `.rodata`, so no unpacking was required. Static linking bundles three components into one ~1.6 MB executable:

- **The bot itself** — command dispatcher, DDoS attack modules, self-replication scanner, persistence, killer/locker/brick modules.
- **toxcore 0.2.22** — the embedded Tox protocol stack (`./toxcore/tox.c`, `DHT.c`, `Messenger.c`, `net_crypto.c`, TCP relay code, etc.), which provides the C2 channel.
- **libsodium + glibc** — cryptography (NaCl/Blake2b) and the C runtime, statically linked so the bot runs on any x86-64 Linux with no dependencies.

The bot bootstraps into the public Tox DHT using a hardcoded list of ~20 bootstrap nodes (IP/domain + 32-byte public key pairs in `.rodata`), befriends the operator's hardcoded Tox ID, and executes commands arriving as Tox friend messages. Command strings observed in the binary: `startkiller`, `stopkiller`, `startlocker`, `brick`, `startscan`, `stopscan`, `stopvse`, `stopwra`, `stopudpts`, `stop_tcp_socket`, `stop_tcp_bypass`, `stop_tcp_syndata`, `stop_tcp_stomp`, `stop_tcp_syn`, `stop_tcp_socket_hold`, `stop_tcp_ack`, `stop_brazilian`, `stop_raknet`, `stop_udp_hex`, `stop_udp_raw`, `stop_udp_plain`, `stop_udp_bypass`, `stop_openvpn`. Per the framework documentation, attacks start with matching verbs (`vse`, `wra`, `tcp_syn`, ...) taking target/port/thread/duration arguments — consistent with the "[+] <attack> attack started on %s:%s" status strings the bot sends back.

## Capabilities

- **DDoS — 18 attack vectors (confirmed by string evidence and status messages):**
  - UDP: VSE (Source Engine query flood), UDPTS (TeamSpeak 3), RakNet, OpenVPN, UDP Hex, UDP Raw, UDP Plain, UDP Bypass.
  - TCP: WRA (SYN flood with TCP options), TCP SYN, TCP ACK, TCP SYN Data, TCP Socket, TCP Socket Hold, TCP Bypass (Slowloris-style), TCP Stomp, Brazilian Handshake.
- **Self-replication (worm):** a scanner module (`startscan` / `stopscan`, "[+] Self-replication scanner started") fires at least 12 router/IoT exploit payloads, each pulling and executing `hxxp://91[.]208[.]197[.]218/bins/kaf.sh`:
  - GPON `POST /GponForm/diag_Form?images/` (CVE-2018-10561/10562 class)
  - Router diag ping injection (`XWebPageName=diag&diag_action=ping&...dest_host=;wget ...`)
  - UPnP `AddPortMapping` command injection (two SOAP variants, ports 80 and 49152)
  - Netgear `setup.cgi?todo=syscmd`
  - `POST /ctrlt/DeviceUpgrade_1` with `NewStatusURL` injection (ZTE/UPnP upgrade)
  - TR-064 `POST /UD/act?1` `SetNTPServers` injection
  - HNAP (`POST /HNAP1/`, `SOAPAction: http://purenetworks[.]com/HNAP1/...`) — D-Link
  - `GET /language/Swedish&&...` (D-Link HNAP variant)
  - `GET /shell?...`, `GET /cgi-bin/;...`, `GET /board.cgi?cmd=...`
- **Killer module:** `startkiller` / `stopkiller`; scans `/proc` (strings include `rm -rf /proc/*`, `/proc/self/exe`) — consistent with Mirai-style killing of competing bots. Exact target list not resolved statically (inference).
- **Locker module:** `startlocker`, "[+] Locker module started". Adjacent strings bring interfaces down (`ifconfig eth0/wlan0 down`, `ip link set ... down`) and set `iptables -P INPUT/OUTPUT/FORWARD DROP` — i.e. it severs the host's network access (inference from string proximity; not confirmed by disassembly).
- **Host destruction ("brick"):** the `brick` command prints "[+] BRICKER ACTIVATED - System will be destroyed" and runs a destructive shell sequence: `rm -rf /dev/*`, `rm -rf /bin /sbin /usr/bin /usr/sbin /boot /lib /lib64`, `rm -rf /etc /var /home /root`, overwrites `/dev/sda` and `/dev/hda`, drops all iptables chains, disables kernel panic handlers, then forces an immediate reboot via `echo b > /proc/sysrq-trigger`.
- **Persistence (three redundant methods):**
  - systemd: writes a unit to `/etc/systemd/system` with `Description=Toxnet Bot`, `Restart=always`, then `systemctl daemon-reload`, `systemctl enable toxnet.service`, `systemctl start toxnet.service`.
  - cron: `@reboot <path>` plus `*/5 * * * * <path>` (re-runs every 5 minutes).
  - `/etc/rc.local` for legacy init systems.
- **Stealth:** masquerades as the kernel thread `[kworker/0:0]`; assigns each bot a randomized human-like name from embedded adjective/color/animal wordlists (e.g. "Silent", "Crimson", "Falcon"); enforces a single instance via the lock file `/tmp/xxeurbmrod`.
- **C2:** fully decentralized, end-to-end-encrypted C2 over the Tox protocol; no central server, no HTTP beacon.

## Anti-analysis techniques

| Technique | Where | How overcome |
| --- | --- | --- |
| Stripped symbol table | ELF header (no `.symtab`) | Analysis driven by `.rodata` strings, which the author left in plaintext |
| Static linking (no dynamic imports to inspect) | ELF program headers | Identified bundled libraries by their assertion strings (`./toxcore/*.c`, `libsodium`, glibc) |
| Process-name masquerade | `.rodata` `[kworker/0:0]` | Noted as a runtime evasion for defenders to detect |
| Randomized bot naming | wordlists in `.rodata` | Noted; makes bot-name-based hunting unreliable |

No packing, encryption of strings, anti-debug, or anti-VM checks were observed. The sample relies on the encrypted Tox channel and masquerading rather than on analyst-facing evasion.

## Command and control

C2 uses the **Tox protocol** (encrypted DHT + onion routing, NaCl cryptography via libsodium). The mechanism below is confirmed by disassembly of `main` (0x401ab0) and the friend-message callback (0x4092d0); code references are given so another analyst can verify. There is no central C2 server to sinkhole — consistent with the ToxNetV2 design.

**Startup sequence (confirmed in `main`):**

1. `tox_new(NULL, NULL)` at 0x401b7b — all toxcore 0.2.22 defaults: UDP enabled, local discovery enabled, IPv6 enabled, hole punching enabled, `proxy_type=NONE` (no Tor/proxy on the bot side), `tcp_port=0`, bind range 33445–33545, `savedata_type=NONE` — the bot generates a **fresh random Tox keypair on every run**.
2. The bot walks a static bootstrap table (below) and calls **both `tox_bootstrap` (0x40c6d0) and `tox_add_tcp_relay` (0x40c870)** for every node (loop at 0x401bb8–0x401c10, keys decoded with `sodium_hex2bin` at 0x401bd8).
3. It decodes the 76-hex-char operator Tox address (`.data` pointer at 0x589888 → `.rodata` 0x53ecd8) with an `sscanf("%2hhx")` loop (helper 0x40b1d0) and calls **`tox_friend_add` at 0x401c50** with the 9-byte friend-request message **"Incoming"** — that is the check-in.
4. It registers a friend-message callback (0x4092d0, via `tox_callback_friend_message` at 0x401c2a) and enters the `tox_iterate` loop. The bot's Tox name is set to **"LINUX"**; a random adjective/color/animal name (e.g. "SilentFalcon") is composed by the generator at 0x40aa30 and set as the status message.

**Operator authentication (confirmed):** the message callback hex-encodes the sender's public key and `strcmp`s it against the 64-char operator key (`.rodata` 0x53ec90) at 0x40938f. Messages from anyone else are silently dropped. Only then are commands dispatched (`startkiller`, `brick`, `startscan`, `vse`, `wra`, ...). No fallback or secondary C2 exists — every hardcoded IP/domain in the binary is accounted for below.

**Operator Tox address (checksum valid per Tox spec):**

```
61D4A3B2735F5248FB7AA505151ACBBFBF45176FBA6A05E67B59F6B20892C325E6CE44D0904F
├─ public key  61D4A3B2735F5248FB7AA505151ACBBFBF45176FBA6A05E67B59F6B20892C325
├─ nospam      E6CE44D0
└─ checksum    904F  (valid)
```

**Bootstrap node table** — static array of 23 records at `.data` 0x589100, stride 0x50: `{char *host; uint16 port (host order); char pubkey_hex[65]}`. All 23 nodes are well-known public Tox bootstrap servers — the bot blends into legitimate Tox traffic.

| # | Host | Port | DHT public key |
| --- | --- | --- | --- |
| 0 | 144[.]217[.]167[.]73 | 33445 | 7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C |
| 1 | tox[.]abilinski[.]com | 33445 | 10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E |
| 2 | tox1[.]mf-net[.]eu | 33445 | B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506 |
| 3 | 3[.]0[.]24[.]15 | 33445 | E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D |
| 4 | 139[.]162[.]110[.]188 | 33445 | F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55 |
| 5 | tox2[.]mf-net[.]eu | 33445 | 70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F |
| 6 | 144[.]172[.]88[.]203 | 33445 | 2016A0F2797EE3A8B004BA623F11AAFC8146F1B8F45107232A1A1AECCE856674 |
| 7 | 91[.]146[.]66[.]26 | 33445 | B5E7DAC610DBDE55F359C7F8690B294C8E4FCEC4385DE9525DBFA5523EAD9D53 |
| 8 | 172[.]104[.]215[.]182 | 33445 | DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239 |
| 9 | tox[.]initramfs[.]io | 33445 | 3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25 |
| 10 | tox3[.]mf-net[.]eu | 33445 | F4FC9398B7167668ED2BCF85634E04D4CDCDD2F95DA5F305BD234888B6E6A771 |
| 11 | 188[.]214[.]122[.]30 | 33445 | 2A9F7A620581D5D1B09B004624559211C5ED3D1D712E8066ACDB0896A7335705 |
| 12 | 43[.]198[.]227[.]166 | 33445 | AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E |
| 13 | 95[.]181[.]230[.]108 | 33445 | B5FFECB4E4C26409EBB88DB35793E7B39BFA3BA12AC04C096950CB842E3E130A |
| 14 | tox[.]hidemybits[.]com | **443** | 5D57B95EE4A7F37BA031DAD0CBD9510A9C96FFE09C1CE24A9C33746F39817D6E |
| 15 | tox4[.]mf-net[.]eu | 33445 | DCD342A0D5E2AA8E35C2BD2C7988F906EEB631B35100170A7F30E77D7F596442 |
| 16 | 188[.]245[.]84[.]166 | 33445 | 96B66D300BA2B59B98FC42DB1325E7092388F0379593E680ABDBEA03B9C9CE03 |
| 17 | 86[.]107[.]187[.]54 | 33445 | 2C0F90965134C7BEFAFE72B077A19221628D7045BB51C1165A2C75CDB2B32634 |
| 18 | 119[.]59[.]101[.]63 | 33445 | 197F746696062FA3BD07BB3BC0656ABD6692B4DAA27DACF0F474754F2B09B060 |
| 19 | 167[.]17[.]40[.]142 | 33445 | E84453123B44A47120FFB469CBCDEEF078D3785D7AD7F6C5B2351CB5DDE2C54C |
| 20 | 172[.]86[.]77[.]39 | 33445 | AFFD3FAD3460E62A894E439534B27E5A5DCFE379C1C0FB78DEF1B150A87E900F |
| 21 | 145[.]239[.]1[.]105 | 33445 | 1658A9A64046C20F48FB2A47E56045233AB0AC0706974FC5904F9E74F452D908 |
| 22 | 5[.]19[.]249[.]240 | **38296** | DA98A4C0CD7473A133E115FEA2EBDAEEA2EF4F79FD69325FC070DA4DE4BA3238 |

**Payload host (actor infrastructure):** hxxp://91[.]208[.]197[.]218/bins/kaf[.]sh — referenced 14 times, exclusively inside the 12 exploit-sender functions of the self-replication scanner (0x408290–0x408b30). The bot itself never downloads it; only exploited routers fetch it. There is no update mechanism.

**Scanner network behavior (confirmed):** 12 exploit senders over a shared TCP connect helper (0x408180, 5 s timeout) with hardcoded target ports **80, 81, 5555, 7574, 8080, 8443, 37215, 49152, 52869**. Target IPs are random: the last three octets are `rand()%255`; the first octet comes from curated tables (GPON-8080: 187/189/200/201/207; GPON-80: 1/2/5/31/37/41/42; general dispatcher: `rand()%233`). The scan loop (0x4090e0) forks, runs 10 rounds of 3 passes with 100 ms gaps, sleeps 12 s, and repeats; `stopscan` kills the child with `SIGKILL`.

**Attack traffic:** 10 raw-socket sites (`SOCK_RAW` + `IP_HDRINCL`, full header forgery; 3 UDP, 7 TCP). The VSE module hardcodes destination port **27015** with the Source Engine `\xff\xff\xff\xff"e Query"` payload; all other attack ports come from C2 arguments. Five attack modules spoof source IP **192[.]168[.]3[.]100** (an unchanged framework placeholder).

## Indicators of compromise (IOCs)

| Indicator | Type |
| --- | --- |
| 0a70e73d780b9beed234b0376b0136e39f09d1961c08c8505cad5849ff51a562 | SHA-256 |
| ef14353452fee94bccceb6d24f47480e9b2863a8 | SHA-1 |
| 868846ceba7491c7e37b48dd08688b38 | MD5 |
| `61D4A3B2735F5248FB7AA505151ACBBFBF45176FBA6A05E67B59F6B20892C325E6CE44D0904F` | Tox C2 ID |
| hxxp://91[.]208[.]197[.]218/bins/kaf[.]sh | payload download URL |
| 91[.]208[.]197[.]218 | IPv4 (actor infrastructure) |
| toxnet.service | systemd persistence unit |
| `Description=Toxnet Bot` | systemd unit content marker |
| `@reboot <bot path>` + `*/5 * * * * <bot path>` | cron persistence entries |
| /etc/rc[.]local entry | legacy persistence |
| /tmp/xxeurbmrod | single-instance lock file |
| process named `[kworker/0:0]` (as a userspace process) | runtime masquerade |
| /tmp/kaf[.]sh, /var/tmp/kaf[.]sh | dropper script names on re-infected devices |
| outbound 33445/tcp+udp (21 nodes), 443 (tox[.]hidemybits[.]com), 38296 (5[.]19[.]249[.]240) | Tox bootstrap/relay traffic |
| Tox friend request containing the literal message `Incoming` | bot check-in to operator |
| Tox self name `LINUX` | bot identity on the Tox network |
| scanner probes to tcp/80, 81, 5555, 7574, 8080, 8443, 37215, 49152, 52869 (randomized IPs) | self-replication exploit traffic |
| UDP to port 27015 with payload `\xff\xff\xff\xffe` (Source Engine query) | VSE attack traffic |
| spoofed source IP 192[.]168[.]3[.]100 in raw attack packets | attack traffic artifact |
| raw sockets with IP_HDRINCL from a userspace process | attack module socket behavior |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Impact | Network Denial of Service | T1498 |
| Impact | Disk Wipe: Disk Structure Wipe / Disk Content Wipe (`/dev/sda`, `rm -rf /`) | T1561.002 / T1561.001 |
| Impact | System Shutdown/Reboot (`echo b > /proc/sysrq-trigger`) | T1529 |
| Impact | Inhibit System Recovery (panic handler/sysctl tampering, iptables DROP) | T1490 |
| Command and Control | Application Layer Protocol (Tox) | T1071 |
| Command and Control | Encrypted Channel (NaCl via Tox) | T1573 |
| Persistence | Create or Modify System Process: Systemd Service | T1543.002 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Persistence | Boot or Logon Initialization Scripts: RC Scripts | T1037.004 |
| Defense Evasion | Masquerading (`[kworker/0:0]`, randomized bot names) | T1036 |
| Defense Evasion | Obfuscated Files or Information (stripped binary) | T1027 |
| Lateral Movement / Reconnaissance | Exploitation of Remote Services (router exploit scanner) | T1210 |
| Discovery | Network Service Discovery (internet-wide scan) | T1046 |
| Resource Development | Compromise Infrastructure (payload host) | T1584 |

## Detection and response recommendations

- **Contain first.** Any infected host may already be DDoS-ing others and may be `brick`ed remotely at any time. Isolate the host from the network; do not assume a reboot cleans it (systemd + cron + rc.local persistence).
- **Block and alert** on `91[.]208[.]197[.]218` and on outbound 33445/tcp+udp to the listed bootstrap IPs. Alert on any internal host resolving `tox[.]initramfs[.]io`, `tox[.]hidemybits[.]com`, `tox*mf-net[.]eu` or `tox[.]abilinski[.]com` — most environments have no legitimate Tox use.
- **Hunt on hosts** for: `toxnet.service`, the string `Toxnet Bot` in `/etc/systemd/system/`, `@reboot`/`*/5 * * * *` cron entries pointing to unexpected binaries, `/tmp/xxeurbmrod`, and userspace processes whose `comm` is `[kworker/0:0]` (real kworkers have no userspace maps; check `/proc/<pid>/exe`).
- **Rebuild, don't clean.** Given the brick/killer modules and root-level persistence, reimage infected hosts and rotate credentials. Inspect routers and IoT devices on the same network for `kaf.sh` infection.
- **Protect the edge.** The scanner exploits long-patched router CVEs (GPON, Netgear `setup.cgi`, D-Link HNAP, TR-064). Patch or replace exposed devices and disable WAN-side administration.

YARA rule for this bot:

```yara
rule ToxNetV2_bot_linux {
    meta:
        description = "ToxNetV2 DDoS bot (Linux ELF) — kaf.sh self-replication, Tox C2"
        family = "ToxNetV2"
        sha256 = "0a70e73d780b9beed234b0376b0136e39f09d1961c08c8505cad5849ff51a562"
    strings:
        $tox1 = "Description=Toxnet Bot" ascii
        $tox2 = "[kworker/0:0]" ascii
        $kaf  = "/bins/kaf.sh" ascii
        $atk1 = "[+] BRICKER ACTIVATED" ascii
        $atk2 = "[+] VSE attack started on" ascii
        $atk3 = "stop_tcp_socket_hold" ascii
        $c2   = "61D4A3B2735F5248FB7AA505151ACBBFBF45176FBA6A05E67B59F6B20892C325" ascii
    condition:
        uint32(0) == 0x464c457f and 3 of them
}
```

## Analysis notes and limitations

- **Static-only analysis.** The sample is a Linux ELF and this host is macOS; sogen (the skill's dynamic engine) emulates Windows user space and cannot run it. The sample was never executed. Behavioral claims rest on string and disassembly evidence in the binary, cross-checked against the public ToxNetV2 framework source.
- **Confirmed by disassembly in the second pass:** the C2 startup sequence and operator authentication (friend-add with "Incoming", pubkey `strcmp` gate, command dispatcher), the full 23-node bootstrap table with ports and DHT keys, the Tox options (no proxy, fresh keypair per run), the scanner's ports and target-IP generation, and the raw-socket attack behavior. Address-level evidence is in `findings_c2-identity.md`, `findings_bootstrap-tox-options.md`, and `findings_network-surface.md` in the analysis directory.
- **Inferred, not confirmed:** the exact body of the killer and locker modules (string adjacency only), and the runtime behavior of the DDoS worker threads (per-packet rates, duration handling) — the modules' sockets and setup are confirmed, their inner loops were not fully traced. A follow-up with a Linux sandbox (e.g. an isolated VM with a faked Tox bootstrap node) would confirm traffic on the wire.
- The Tox bootstrap IPs/domains are public, volunteer-run infrastructure — block them in corporate environments, but do not treat them as actor-owned. The actor-specific indicators are the Tox ID and `91[.]208[.]197[.]218`.

## Appendix: tooling

| Tool | Use |
| --- | --- |
| static_triage.py (malware-analysis skill) under uv 0.11.32 (`--with pefile capstone yara-python`) | hashing, format ID, string triage, YARA |
| GNU `strings` | full string extraction (`strings_all.txt`, 5,492 strings) |
| pyelftools (uv ephemeral env) | ELF headers, sections, entry point, `.comment` |
| Web search / framework README | family attribution and command-set corroboration |
| capstone + pyelftools (uv ephemeral env), 3-agent RE swarm | xref scanning, disassembly of `main`/callbacks, bootstrap-table and Tox-options recovery |

Analysis directory: `/Users/dcooper/Documents/scripts/bot-linux-analysis/` (sample copy `sample.bin`, non-executable; `triage.json`; `strings_all.txt`; `report.md`; `findings_c2-identity.md`, `findings_bootstrap-tox-options.md`, `findings_network-surface.md` — address-level disassembly evidence).
