# Nmap to Obsidian

Turn Nmap XML scans into an Obsidian vault: one note per host, a network graph, and a summary
of what matters on the network. Built for internal pentests and red team work, where you scan
the same ranges many times and want one place that keeps track of everything.

```bash
python converter.py 10.10.10.0.xml 192.168.13.0.xml
```

> **Status: alpha.** Works well on the scans it was built with, but it still needs testing on
> more real networks. Issues with a scrubbed XML sample are very welcome.

## What makes it different

Other tools turn a scan into tables or a single report. This one keeps a **living vault**:

- **Incremental.** Run it on every new scan. Hosts are updated in place, nothing is duplicated,
  and the order you pass files in does not matter (they are sorted by scan time).
- **Roles with evidence.** About 70 asset types (Domain Controller, ESXi, vCenter, MSSQL, SWIFT,
  core banking, HSM, Veeam, SCCM, firewalls, printers, cameras, OT/ICS...). Every role shows what
  proved it, and weak evidence is marked as a *maybe* instead of a guess presented as fact.
- **Honest OS data.** What a host says about itself (SMB, VMware, SNMP) beats an OS fingerprint
  guess, and each OS shows where it came from.
- **History.** Ports keep first and last seen dates, closed ports stay with their closing date,
  OS and version changes are logged. Nothing is deleted.
- **Handle With Care.** Fragile and critical devices (routers and switches, printers, OT, ATMs,
  old Windows, BMCs) are collected into an exclude list you can paste into Nessus.
- **Web stack.** Server, language, framework and CMS from headers and cookies
  (`nginx 1.18.0, PHP 7.4.3, Laravel`), each with its proof. Devices show what they are instead.
- **Real world scans.** Unfinished scans (still running or stopped) are imported as far as they
  got, with the list of targets left. `-Pn` targets that never answered do not become fake hosts.

Single file, standard library only, Python 3.9+.

## Install

```bash
cd nmap-obsidian
pip install defusedxml   # optional, recommended for scan files you did not make yourself
python converter.py -h
```

## Recommended scans

The tool can only show what Nmap collected. For a full picture of a range, scan in passes; the
converter merges all of them into the same notes.

```bash
# 1. All TCP ports, no ping (finds hosts that ignore ping)
sudo nmap -Pn -sS -p- --min-rate 1000 --max-retries 2 -n -v -oA 01-ports 10.10.10.0/24
grep "Ports:.*/open/" 01-ports.gnmap | cut -d' ' -f2 > live.txt
grep -oP '\d+(?=/open)' 01-ports.gnmap | sort -un | paste -sd, > ports.txt

# 2. Check Handle With Care in summary.md, put fragile hosts in exclude.txt

# 3. Deep scan on open ports only
sudo nmap -Pn -sV -O --traceroute --script "default,http-headers,smb-protocols" -v \
  -p $(cat ports.txt) -iL live.txt --excludefile exclude.txt -oA 02-deep

# 4. Top UDP ports (SNMP is how many switches and printers identify themselves)
sudo nmap -Pn -sU --top-ports 50 -sV -sC -v -iL live.txt --excludefile exclude.txt -oA 03-udp

python converter.py 01-ports.xml 02-deep.xml 03-udp.xml -o ClientA/Nmap_Nodes
```

Why: `-sV` and scripts are the evidence for roles and web stack, `-v` records down hosts,
`--traceroute` finds routers, and `-oA` keeps a `.gnmap` so `nmap --resume` works.

Only scan networks you are authorized to test.

## What you get

```
Nmap_Nodes/
├── summary.md      OS counts, roles by group, Handle With Care, findings, web stack, changes, tags
├── hosts.md        every host ever seen (plain table, adds no graph hub)
├── hosts.txt       the same IPs, one per line, for nmap -iL, nxc, Nessus
├── scans.md        every imported file and whether nmap finished it
├── .netmap/        history (hidden from Obsidian, travels with the vault)
└── 10.0.0.0/10.10.0.0/10.10.10.0/
    ├── 10.10.10.0_24.md
    └── 10.10.10.5.md
```

A host note:

```markdown
---
type: network-node
ip: 10.10.10.5
hostname: "dc01.corp.local"
os: "Windows Server 2016 Standard 14393"
roles: ["dc"]
tags: ["role/dc", "os/windows/server"]
---
# 10.10.10.5

## System Information
- **OS:** Windows Server 2016 Standard 14393 _(smb-os-discovery)_

## Roles
| Role | Confidence | Evidence |
| --- | --- | --- |
| Domain Controller | confirmed | 88/tcp + 389/tcp + 445/tcp open |

## Open Ports
| Port | Service | Version | First seen | Last seen | Status |
| --- | --- | --- | --- | --- | --- |
| [[Port 445]] (`445/tcp`) | microsoft-ds | N/A | 2026-11-12 09:46 | 2026-11-12 18:06 | open |

## Scan Changes
- 2026-11-12 18:06: fingerprint now says Linux 4.X, kept Windows Server 2016 (smb-os-discovery)

## Notes
Your own notes go here and are never touched.
```

Script output goes into collapsed callouts, so notes stay readable.

## Graph colors

Every host gets tags: `role/<x>`, `maybe/<x>`, `os/<family>`, `web/<tech>`, `caution/<level>`,
`finding`, `status/down`. `summary.md` lists the tags present in your vault with host counts,
and `python converter.py -h` lists every possible one.

In Graph view > Groups, the first matching group wins, so put specific ones on top:

```
tag:#role/dc
tag:#role/esxi OR tag:#role/vcenter
tag:#caution/critical
tag:#os/windows/server
tag:#os/windows
tag:#os/linux
```

Port links (`[[Port 445]]`) connect every host with that port. Turn them off with `-P`.

## Options

| Option | |
| --- | --- |
| `-o DIR` | vault folder (default `Nmap_Nodes`) |
| `-P` | no `[[Port N]]` hub nodes |
| `-v` | print every role, finding and change |
| `-n` | no colors |
| `--prune-ghosts` | delete notes of hosts with no sign they exist (made by `-Pn` scans with older versions); notes you wrote in are kept |

## Safe to edit

- Text under `## Notes` and any `##` section you add are kept on every run.
- Rebuilt every run: System Information, Roles, Scan Findings, Web Stack, Graph Network Links,
  Traceroute Path, Open Ports, Script Output, Scan Changes.
- Notes are found by their `ip:` field, so you can move them between folders.
- Deleting a note also forgets its history.

## Extending

Roles are a list of rules near the top of `converter.py` (`RULES`). A rule is a regex on what
the service says about itself, plus optional port combinations:

```python
rule("gitlab", "GitLab", "Management and backup", text=r"GitLab"),
```

Findings live in `script_findings()`, web technologies in `WEB_TECH`.

## Limitations

- Nmap does not run JavaScript, so React, Vue or Angular front ends are mostly invisible.
- A host that drops every probe on the ports you scanned cannot be told apart from an empty IP.
- Roles depend on `-sV` and scripts. A bare `-sS` scan gives ports and an OS guess, little more.
- IPv6-only hosts are skipped (notes are keyed by IPv4).
- End of support dates are correct as of 2026-11 and need updating over time.
- Very large vaults (tens of thousands of hosts) work, but the Obsidian graph gets slow.

## Your data

A vault holds client data. The `.gitignore` here keeps `Nmap_Nodes/` and scan files out of git;
keep it that way.

## Similar tools

- [nmap-formatter](https://github.com/vdjagilev/nmap-formatter): converts a scan to HTML, CSV,
  Markdown, JSON, Graphviz and more.
- [Nmap2Table](https://github.com/0xMR007/Nmap2Table): scan results as Markdown tables.
- [nmap-plugin](https://github.com/Yasha-ops/nmap-plugin): Obsidian plugin that imports a scan
  into notes and a canvas.
- [Nmap-and-Chill](https://github.com/shhimnothere/Nmap-and-Chill): runs Nmap scans and writes
  reports and Obsidian notes.

## License

MIT.
