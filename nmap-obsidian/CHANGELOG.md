# Changelog

## 3.1 (first public version)

- One note per host in an IP folder tree, incremental and safe to rerun; follows existing vault layouts.
- About 70 roles with evidence and confidence (confirmed / maybe), grouped in summary.md.
- OS with its source; self reported OS beats fingerprint guesses; changes are logged.
- History per host in `.netmap/` (ports first/last seen, closed ports, changes), outside the notes.
- Web stack detection from headers, cookies, generator and auth.
- End of support OS and outdated software findings, legacy Windows caution.
- Routers from traceroute, Handle With Care list and exclude list.
- Unfinished scans imported as far as they got, remaining targets and resume command.
- `-Pn` targets that never answered are skipped; `--prune-ghosts` cleans notes from older versions.
- summary.md, hosts.md, hosts.txt, scans.md; tags for graph groups; NetExec style output.
- Untrusted scan data is sanitized; atomic writes; defusedxml support.
