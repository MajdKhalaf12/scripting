#!/usr/bin/env python3
"""
converter.py  Nmap XML to Obsidian notes and graph, incremental.

    python converter.py scan.xml [more.xml ...] [options]
    python converter.py -h        full help

Single file, standard library only. Install defusedxml (pip install defusedxml)
before parsing scan files you did not produce yourself.
"""
import ipaddress
import json
import os
import re
import shlex
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

try:
    from defusedxml.ElementTree import iterparse as _iterparse
    from defusedxml.common import DefusedXmlException as XMLSecurityError
    SAFE_XML = True
except ImportError:
    _iterparse = ET.iterparse
    XMLSecurityError = ()  # `except ()` catches nothing
    SAFE_XML = False

VERSION = "3.1"
DEFAULT_OUT = "Nmap_Nodes"
EVENT_LIMIT = 25  # events printed per scan file unless -v

# Sections the script rebuilds on every run. Everything else in a host note
# (## Notes and any section you add yourself) is kept verbatim.
GENERATED = {"System Information", "Roles", "Scan Findings", "Web Stack", "Graph Network Links",
             "Traceroute Path", "Open Ports", "Script Output", "Scan Changes"}

# End of support data below is correct as of this month. Update the tables when it ages.
EOL_AS_OF = "2026-11"

# OS evidence strength: what the host says about itself beats a fingerprint guess.
STR_SELF = 3.0      # smb-os-discovery
STR_PRODUCT = 2.5   # vmware-version, snmp-sysdescr, -sV product (ESXi)
STR_FP_HIGH = 2.0   # OS fingerprint, accuracy >= 95
STR_OSTYPE = 1.5    # -sV service ostype ("Windows", "Linux")
STR_FP_LOW = 1.0    # OS fingerprint, accuracy < 95

CAUTION_RANK = {"": 0, "high": 1, "critical": 2}


# ============================================================ terminal ====

class Color:
    on = True


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if Color.on else str(s)


def blue(s): return _c("1;34", s)
def green(s): return _c("1;32", s)
def red(s): return _c("1;31", s)
def yellow(s): return _c("1;33", s)
def bold(s): return _c("1", s)
def dim(s): return _c("2", s)


_MARKS = {"*": blue, "+": green, "-": red, "!": yellow}


def say(kind, target, mark, msg):
    """NetExec style line: KIND  target  [x] message"""
    print(f"{blue(f'{kind:<8}')} {str(target):<17} {_MARKS[mark](f'[{mark}]')} {msg}")


# ========================================================== sanitizing ====

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏ -‮⁦-⁩]")
_MD = re.compile(r"[|`\[\]<{}\\]")  # "<" starts HTML; ">" alone is harmless mid-line
PORT_RE = re.compile(r"[0-9]{1,5}/[a-z0-9]{2,8}")
MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")
TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9]{2}:[0-9]{2}(:[0-9]{2})?)?")


def clean(s, maxlen=200):
    """Untrusted text made safe for frontmatter, tables, links and the terminal."""
    s = _CTRL.sub(" ", str(s or ""))
    s = _MD.sub(" ", s).replace("%%", "% %")
    s = re.sub(r"(^|\s)#+", r"\1", s)  # no accidental #tags
    return re.sub(r"\s+", " ", s).strip()[:maxlen]


def clean_code(s, max_lines=60, max_chars=3000):
    """Untrusted multi-line text for a fenced code block (keeps layout)."""
    s = str(s or "").replace("\r\n", "\n").replace("\r", "\n").replace("\t", "    ")
    s = _CTRL.sub(" ", s).replace("`", "'").replace("%%", "% %")
    lines = [ln.rstrip()[:300] for ln in s.split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    cut = len(lines) > max_lines
    out = "\n".join(lines[:max_lines])
    if len(out) > max_chars:
        out, cut = out[:max_chars], True
    return out + ("\n(truncated)" if cut else "")


def clean_name(s):
    return re.sub(r"[^A-Za-z0-9._-]", "", str(s or ""))[:253].strip(".")


def tag_part(s):
    return re.sub(r"[^a-z0-9_-]+", "-", str(s).lower()).strip("-") or "unknown"


def j(v):
    """JSON is valid YAML and always quotes/escapes correctly."""
    return json.dumps(v, ensure_ascii=False)


def valid_ip(s):
    try:
        return str(ipaddress.IPv4Address(str(s or "").strip()))
    except ValueError:
        return ""


def valid_ip6(s):
    try:
        return str(ipaddress.IPv6Address(str(s or "").strip()))
    except ValueError:
        return ""


def valid_ts(s):
    return s if isinstance(s, str) and TS_RE.fullmatch(s) else ""


def ip_key(ip):
    return int(ipaddress.IPv4Address(ip))


def epoch_iso(v):
    try:
        return datetime.fromtimestamp(int(v)).strftime("%Y-%m-%dT%H:%M:%S")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def short(ts):
    return ts[:16].replace("T", " ") if ts else ""


def dmin(*d):
    d = [x for x in d if x]
    return min(d) if d else ""


def dmax(*d):
    d = [x for x in d if x]
    return max(d) if d else ""


def _list(v):
    return v if isinstance(v, list) else []


def _dict(v):
    return v if isinstance(v, dict) else {}


def write_atomic(path, text):
    folder, name = os.path.split(path)
    tmp = os.path.join(folder, f".{name}.tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def port_sort(key):
    num, proto = key.split("/")
    return (int(num), proto)


def sorted_ports(ports):
    return sorted(ports.items(), key=lambda kv: port_sort(kv[0]))


# ============================================================== OS ====

def _family_one(s):
    s = s.lower()
    if "esxi" in s:
        return "esxi"
    if re.search(r"windows server|server 20\d\d|windows 20\d\d", s):
        return "windows-server"
    if re.search(r"windows (xp|vista|7|8|8\.1|10|11)\b", s):
        return "windows-workstation"
    if "windows" in s:
        return "windows"
    if re.search(r"cisco|ios[- ]x[er]|nx-os|junos|routeros|fortios|pan-os|\bvrp\b|arubaos|edgeos", s):
        return "network-os"
    if "android" in s:
        return "android"
    if "linux" in s:
        return "linux"
    if re.search(r"bsd", s):
        return "bsd"
    if re.search(r"mac os|macos|os x|darwin", s):
        return "macos"
    if re.search(r"z/os|os/400|ibm i\b|i5/os", s):
        return "ibm"
    if re.search(r"aix|solaris|sunos|hp-ux", s):
        return "unix"
    return "other"


def os_family(name):
    """Family of an OS string; "A or B" guesses only get a family if both agree."""
    if not name:
        return "unknown"
    fams = {_family_one(p) for p in re.split(r"\s+or\s+|,\s+", name) if p.strip()}
    if len(fams) == 1:
        return fams.pop()
    if all(f.startswith("windows") for f in fams):
        return "windows"
    return "mixed"


# ========================================================== subnets ====

def subnet_chain(ip):
    """[(network, prefix, is_real_range), ...] from broadest to /24."""
    a, b, c, _ = (int(x) for x in ip.split("."))
    net16 = (f"{a}.{b}.0.0", 16, a == 192 and b == 168)
    net24 = (f"{a}.{b}.{c}.0", 24, False)
    if a == 10:
        return [("10.0.0.0", 8, True), net16, net24]
    if a == 172 and 16 <= b <= 31:
        return [("172.16.0.0", 12, True), net16, net24]
    return [net16, net24]


def seg_name(net, prefix):
    return f"{net}_{prefix}"


def seg_dir(net, prefix):
    return net if prefix != 12 else f"{net}_{prefix}"  # avoid clash with 172.16.0.0/16


# "a.b.c" -> folder that already holds hosts of that /24 (filled in main)
PLACES = {}
# True when the vault was built with the original layout (every range under a /8 folder)
LEGACY_LAYOUT = [False]


def _segment_note(folder, net, prefix, real, parent, segments):
    os.makedirs(folder, exist_ok=True)
    name = seg_name(net, prefix)
    path = os.path.join(folder, f"{name}.md")
    lines = ["---", "type: network-segment", f"cidr: {j(f'{net}/{prefix}')}",
             f"grouping: {'false' if real else 'true'}", "---", "",
             f"# {'Network' if real else 'Group'} {net}/{prefix}"]
    if not real:
        lines += ["", "_Grouping by address prefix, not a confirmed network._"]
    if parent:
        lines += ["", f"Parent: [[{parent}]]"]
    write_atomic(path, "\n".join(lines) + "\n")
    segments[name] = path


def place_host(out, ip, segments):
    """
    Folder for a new host note. It follows the tree already in the vault, whatever
    layout made it (including the original /8 > /16 > /24 one), and only builds
    the folders and segment notes that are missing.
    """
    a, b, c, _ = ip.split(".")
    chain = subnet_chain(ip)
    seg24 = seg_name(*chain[-1][:2])
    key = f"{a}.{b}.{c}"
    if key in PLACES:  # hosts of this /24 already live somewhere: go there
        folder = PLACES[key]
        if seg24 not in segments:
            parent = next((seg_name(n, p) for n, p, _ in reversed(chain[:-1])
                           if seg_name(n, p) in segments), None)
            _segment_note(folder, *chain[-1], parent, segments)
        return folder
    cands = list(chain)
    legacy = chain[0][1] != 8
    if legacy:  # the original layout put every range under a /8 folder
        cands.insert(0, (f"{a}.0.0.0", 8, False))
    base, start, parent = out, (1 if legacy and not LEGACY_LAYOUT[0] else 0), None
    for i in range(len(cands) - 1, -1, -1):
        name = seg_name(*cands[i][:2])
        if name in segments:
            base, start, parent = os.path.dirname(segments[name]), i + 1, name
            break
    folder = base
    for net, prefix, real in cands[start:]:
        folder = os.path.join(folder, seg_dir(net, prefix))
        name = seg_name(net, prefix)
        if name not in segments:
            _segment_note(folder, net, prefix, real, parent, segments)
        parent = name
    PLACES[key] = folder
    return folder


# ====================================================== host records ====

def blank_record(ip):
    return {"v": 3, "ip": ip, "ipv6": [], "mac": "", "vendor": "", "hostname": "",
            "names": [], "domain": "", "os": "", "os_src": "", "os_acc": 0, "os_str": 0,
            "os_seen": "", "build": "", "devtypes": [], "status": "up", "down_since": "",
            "first_seen": "", "last_seen": "", "paths": [], "ports": {},
            "hostscripts": {}, "scans": [], "changes": [], "pending": False, "alive": "",
            "alive_by": ""}


def blank_port():
    return {"service": "unknown", "method": "", "product": "", "version": "", "extra": "",
            "tunnel": "", "ostype": "", "devtype": "", "cpe": [], "scripts": {},
            "first_seen": "", "last_seen": "", "closed_on": ""}


def norm_path(p):
    if not isinstance(p, dict) or not isinstance(p.get("hops"), list):
        return None
    hops = [valid_ip(x) or "*" for x in p["hops"]][:64]
    if not hops:
        return None
    via = next((x for x in hops if x != "*"), "direct")
    return {"via": via, "hops": hops, "seen": valid_ts(p.get("seen"))}


def norm_scripts(d):
    out = {}
    for sid, txt in _dict(d).items():
        sid = re.sub(r"[^A-Za-z0-9_.-]", "", str(sid))[:60]
        if sid and isinstance(txt, str):
            out[sid] = clean_code(txt, max_lines=70, max_chars=3400)
    return out


def norm_port(p):
    p = _dict(p)
    q = blank_port()
    for k in ("service", "product", "version", "extra", "tunnel", "ostype", "devtype"):
        q[k] = clean(p.get(k, ""), 120)
    q["service"] = q["service"] or "unknown"
    q["method"] = p.get("method") if p.get("method") in ("probed", "table") else ""
    q["cpe"] = [clean(c, 120) for c in _list(p.get("cpe"))][:8]
    q["scripts"] = norm_scripts(p.get("scripts"))
    for k in ("first_seen", "last_seen", "closed_on"):
        q[k] = valid_ts(p.get(k))
    return q


def normalize_record(d, ip):
    """Rebuild a record from stored JSON, defensively (never trust the file)."""
    d = _dict(d)
    r = blank_record(ip)
    r["ipv6"] = [x for x in (valid_ip6(v) for v in _list(d.get("ipv6"))) if x][:8]
    mac = str(d.get("mac", ""))
    r["mac"] = mac if MAC_RE.fullmatch(mac) else ""
    r["vendor"] = clean(d.get("vendor"), 80)
    r["hostname"] = clean_name(d.get("hostname"))
    r["names"] = [n for n in (clean_name(x) for x in _list(d.get("names"))) if n][:10]
    r["domain"] = clean_name(d.get("domain"))
    r["os"] = clean(d.get("os"), 120)
    r["os_src"] = clean(d.get("os_src"), 60)
    for k, hi in (("os_acc", 100.0), ("os_str", STR_SELF)):
        try:
            r[k] = max(0, min(hi, float(d.get(k, 0))))
        except (TypeError, ValueError):
            r[k] = 0
    r["os_acc"] = int(r["os_acc"])
    r["os_seen"] = valid_ts(d.get("os_seen"))
    r["build"] = clean(d.get("build"), 40)
    r["devtypes"] = [clean(x, 40) for x in _list(d.get("devtypes"))][:6]
    r["status"] = "down" if d.get("status") == "down" else "up"
    for k in ("down_since", "first_seen", "last_seen"):
        r[k] = valid_ts(d.get(k))
    r["paths"] = [p for p in map(norm_path, _list(d.get("paths"))) if p][:8]
    r["ports"] = {k: norm_port(v) for k, v in _dict(d.get("ports")).items()
                  if isinstance(k, str) and PORT_RE.fullmatch(k)}
    r["hostscripts"] = norm_scripts(d.get("hostscripts"))
    r["scans"] = [{"file": clean(s.get("file"), 80), "at": valid_ts(s.get("at"))}
                  for s in _list(d.get("scans")) if isinstance(s, dict)][-20:]
    r["pending"] = d.get("pending") is True
    r["alive"] = "yes" if d.get("alive") == "yes" else ""
    r["alive_by"] = clean(d.get("alive_by"), 160)
    r["changes"] = [{"at": valid_ts(c.get("at")), "text": clean(c.get("text"), 240)}
                    for c in _list(d.get("changes")) if isinstance(c, dict)][-100:]
    return r


# ================================================================ XML ====

def _script_elems(sc):
    elems = {}
    for e in sc.iter("elem"):
        k = e.get("key")
        if k and k not in elems:
            elems[k] = (e.text or "").strip()
    return elems


def _absorb_script(ob, sid, elems, text):
    """Facts a host states about itself through scripts."""
    if sid == "smb-os-discovery":
        name = elems.get("os") or (re.search(r"OS: (.+)", text) or [None, ""])[1]
        name = re.sub(r"\s*\([^)]*LAN Manager\)", "", name or "")
        if name:
            ob["cands"].append({"name": clean(name, 120), "src": "smb-os-discovery",
                                "acc": 100, "str": STR_SELF})
        for k in ("fqdn",):
            if elems.get(k):
                ob["script_names"].append(clean_name(elems[k]))
        if elems.get("domain_dns"):
            ob["domain"] = clean_name(elems["domain_dns"])
    elif sid.endswith("-ntlm-info"):
        if elems.get("DNS_Computer_Name"):
            ob["script_names"].append(clean_name(elems["DNS_Computer_Name"]))
        if elems.get("DNS_Domain_Name"):
            ob["domain"] = ob["domain"] or clean_name(elems["DNS_Domain_Name"])
        if elems.get("Product_Version"):
            ob["build"] = clean(elems["Product_Version"], 40)
    elif sid == "vmware-version":
        m = re.search(r"Server version: (.*ESXi.*)", text)
        if m:
            ob["cands"].append({"name": clean(m.group(1), 120), "src": "vmware-version",
                                "acc": 100, "str": STR_PRODUCT})
    elif sid == "snmp-sysdescr":
        first = next((ln.strip() for ln in text.split("\n") if ln.strip()), "")
        if first and _family_one(first) == "network-os":
            ob["cands"].append({"name": clean(first, 120), "src": "snmp-sysdescr",
                                "acc": 100, "str": STR_PRODUCT})
    elif sid == "ldap-rootdse":
        m = re.search(r"defaultNamingContext: ((?:DC=[^,\n]+,?)+)", text)
        if m and not ob["domain"]:
            ob["domain"] = clean_name(".".join(x[3:] for x in m.group(1).split(",") if x))
        m = re.search(r"dnsHostName: (\S+)", text)
        if m:
            ob["script_names"].append(clean_name(m.group(1)))


def _read_scripts(parent, ob):
    out = {}
    for sc in parent.findall("script"):
        sid = re.sub(r"[^A-Za-z0-9_.-]", "", sc.get("id", ""))[:60]
        if not sid:
            continue
        text = clean_code(sc.get("output", ""))
        out[sid] = text
        _absorb_script(ob, sid, _script_elems(sc), text)
    return out


def parse_host(host, meta):
    st = host.find("status")
    state = st.get("state", "up") if st is not None else "up"
    reason = st.get("reason", "") if st is not None else ""
    ip, ipv6, mac, vendor = "", [], "", ""
    for addr in host.findall("address"):
        t, a = addr.get("addrtype"), addr.get("addr", "")
        if t == "ipv4":
            ip = valid_ip(a)
        elif t == "ipv6":
            v6 = valid_ip6(a)
            if v6 and v6 not in ipv6:
                ipv6.append(v6)
        elif t == "mac":
            mac = a if MAC_RE.fullmatch(a) else ""
            vendor = clean(addr.get("vendor", ""), 80)
    if not ip:
        return None  # IPv6-only hosts are skipped (notes are keyed by IPv4)
    seen = epoch_iso(host.get("endtime")) or epoch_iso(host.get("starttime")) or meta["start"]
    if state != "up":
        return {"state": "down", "ip": ip, "seen": seen, "file": meta["file"]}

    ob = {"state": "up", "ip": ip, "ipv6": ipv6, "mac": mac, "vendor": vendor,
          "hostname": "", "names": [], "script_names": [], "domain": "", "build": "",
          "cands": [], "os": None, "devtypes": [], "paths": [], "ports": {},
          "closed": [], "hostscripts": {}, "seen": seen, "file": meta["file"], "hint": False}

    ptr = ""
    for hn in host.findall("hostnames/hostname"):
        n = clean_name(hn.get("name", ""))
        if not n:
            continue
        if hn.get("type") == "PTR" and not ptr:
            ptr = n
        if n not in ob["names"]:
            ob["names"].append(n)

    om = host.find("os/osmatch")
    if om is not None:
        try:
            acc = max(0, min(100, int(om.get("accuracy", 0))))
        except ValueError:
            acc = 0
        name = clean(om.get("name", ""), 120)
        if name:
            ob["cands"].append({"name": name, "src": "fingerprint", "acc": acc,
                                "str": STR_FP_HIGH if acc >= 95 else STR_FP_LOW})
        for oc in om.findall("osclass"):
            try:
                oacc = int(oc.get("accuracy", 0))
            except ValueError:
                oacc = 0
            t = clean(oc.get("type", ""), 40).lower()
            if t and oacc >= 90 and t not in ob["devtypes"]:
                ob["devtypes"].append(t)

    hops = []
    for hop in host.findall("trace/hop"):
        try:
            ttl = int(hop.get("ttl", 0))
        except ValueError:
            continue
        if ttl < 1 or ttl > 64 or len(hops) >= ttl:
            continue
        while len(hops) < ttl - 1:
            hops.append("*")
        hops.append(valid_ip(hop.get("ipaddr", "")) or "*")
    while hops and hops[-1] == ip:
        hops.pop()
    if hops:
        ob["paths"] = [{"via": next((h for h in hops if h != "*"), "direct"),
                        "hops": hops, "seen": seen}]

    for port in host.findall("ports/port"):
        pst = port.find("state")
        pstate = pst.get("state") if pst is not None else ""
        pid, proto = port.get("portid", ""), port.get("protocol", "")
        if not (re.fullmatch(r"[0-9]{1,5}", pid) and re.fullmatch(r"[a-z0-9]{2,8}", proto)):
            continue
        key = f"{int(pid)}/{proto}"
        if pstate in ("open", "closed", "unfiltered"):
            ob["responded"] = True  # an answer (SYN/ACK or RST) came back from this IP
            ob.setdefault("first_open" if pstate == "open" else "first_other", f"{key} {pstate}")
        if pstate == "closed":
            ob["closed"].append(key)
            continue
        if pstate != "open":
            continue
        p = blank_port()
        svc = port.find("service")
        if svc is not None:
            p["service"] = clean(svc.get("name", ""), 40) or "unknown"
            p["method"] = svc.get("method") if svc.get("method") in ("probed", "table") else ""
            p["product"] = clean(svc.get("product", ""), 120)
            p["version"] = clean(svc.get("version", ""), 60)
            p["extra"] = clean(svc.get("extrainfo", ""), 80)
            p["tunnel"] = clean(svc.get("tunnel", ""), 10)
            p["ostype"] = clean(svc.get("ostype", ""), 40)
            p["devtype"] = clean(svc.get("devicetype", ""), 40)
            p["cpe"] = [clean(c.text, 120) for c in svc.findall("cpe") if c.text][:8]
            if p["ostype"] and p["method"] == "probed":
                ob["cands"].append({"name": p["ostype"], "src": f"{key} service", "acc": 0,
                                    "str": STR_OSTYPE})
            if re.search(r"VMware ESXi", p["product"]):
                ob["cands"].append({"name": f"VMware ESXi {p['version']}".strip(),
                                    "src": f"{key} service", "acc": 0, "str": STR_PRODUCT})
        p["scripts"] = _read_scripts(port, ob)
        ob["ports"][key] = p

    hs = host.find("hostscript")
    if hs is not None:
        ob["hostscripts"] = _read_scripts(hs, ob)

    for n in ob["script_names"]:
        if n and n not in ob["names"]:
            ob["names"].append(n)
    ob["hostname"] = ptr or next((n for n in ob["script_names"] if n), "") or \
        (ob["names"][0] if ob["names"] else "")
    if ob["cands"]:
        ob["os"] = max(ob["cands"], key=lambda c: (c["str"], c["acc"]))
    # -Pn makes nmap call every target "up" (reason user-set) without any reply.
    # Only a real answer proves the host exists: a discovery reply, an open, closed
    # or unfiltered port, a MAC (ARP answered), an OS match or host script output.
    ob["evidence"] = bool(reason != "user-set" or ob.get("responded") or mac
                          or host.find("os/osmatch") is not None or ob["hostscripts"])
    # what made it count as alive, shown in the note so you can judge it
    if ob.get("first_open"):
        ob["alive_by"] = f"open port {ob['first_open'].split()[0]}"
    elif mac:
        ob["alive_by"] = "MAC address (answered ARP)"
    elif host.find("os/osmatch") is not None:
        ob["alive_by"] = "OS fingerprint"
    elif ob["hostscripts"]:
        ob["alive_by"] = "host script output"
    elif ob.get("first_other"):
        ob["alive_by"] = (f"only {ob['first_other'].replace('closed', 'closed (TCP reset)')}: a firewall "
                          "answering for every IP looks the same")
    elif reason and reason != "user-set":
        weak = reason in ("reset", "conn-refused")
        ob["alive_by"] = f"discovery reply ({clean(reason, 30)})" + (
            ": a firewall answering for every IP looks the same" if weak else "")
    else:
        ob["alive_by"] = ""
    if not ob["evidence"]:
        return {"state": "silent", "ip": ip, "seen": seen, "file": meta["file"]}
    return ob


def scan_meta(path):
    meta = {"path": path, "file": clean(os.path.basename(path), 80), "start": "", "args": "",
            "args_raw": ""}
    try:
        for _, el in _iterparse(path, events=("start",)):
            if el.tag == "nmaprun":
                meta["start"] = epoch_iso(el.get("start"))
                meta["args_raw"] = _CTRL.sub(" ", el.get("args", ""))[:4000]
                meta["args"] = clean(meta["args_raw"], 300)
            break
    except Exception:
        pass
    if not meta["start"]:
        try:
            meta["start"] = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%dT%H:%M:%S")
        except OSError:
            pass
    return meta


def iter_hosts(meta):
    """
    Stream hosts one by one. Complete hosts before a truncation are still used.
    Also records how the file ended, in meta:
      kind       "" (fine), "empty", "not-xml", "not-nmap", "unsafe"
      complete   nmap wrote its end marker (<finished>)
      truncated  the XML stops in the middle
      last_ip    last host written, in file order (up or down)
    """
    meta.update(kind="", complete=False, truncated=False, exit="", error="", total=None,
                up_total=None, progress="", last_ip="", seen_ips=set(), root="",
                hint_ips=set(), done_up=set(), silent=0)
    try:
        if os.path.getsize(meta["path"]) == 0:
            meta["kind"] = "empty"
            return
    except OSError:
        meta["kind"] = "missing"
        return
    root = None
    try:
        for event, elem in _iterparse(meta["path"], events=("start", "end")):
            if event == "start":
                if root is None:
                    root = elem
                    if elem.tag != "nmaprun":
                        meta["kind"], meta["root"] = "not-nmap", clean(elem.tag, 40)
                        return
                continue
            tag = elem.tag
            if tag == "host":
                ob = parse_host(elem, meta)
                elem.clear()
                root.clear()  # drop finished hosts, they pile up under <nmaprun> otherwise
                if ob:
                    meta["last_ip"] = ob["ip"]
                    meta["seen_ips"].add(ob["ip"])
                    if ob["state"] in ("up", "silent"):
                        meta["done_up"].add(ob["ip"])
                    if ob["state"] == "silent":
                        meta["silent"] += 1
                    yield ob
            elif tag == "hosthint":
                # nmap writes this as soon as discovery finds a host up, long before the
                # host's port scan ends: the host exists, its ports are not known yet
                ob = parse_host(elem, meta)
                elem.clear()
                root.clear()
                if ob and ob["state"] == "up" and ob["ip"] not in meta["done_up"]:
                    ob["hint"] = True
                    meta["hint_ips"].add(ob["ip"])
                    yield ob
            elif tag == "taskprogress":
                meta["progress"] = f"{clean(elem.get('task'), 60)} {clean(elem.get('percent'), 8)}%"
            elif tag == "finished":
                meta["complete"] = True
                meta["exit"] = clean(elem.get("exit"), 20)
                meta["error"] = clean(elem.get("errormsg"), 200)
            elif tag == "hosts":
                try:
                    meta["total"] = int(elem.get("total", ""))
                    meta["up_total"] = int(elem.get("up", ""))
                except ValueError:
                    pass
    except XMLSecurityError as e:
        meta["kind"], meta["error"] = "unsafe", clean(e, 120)
    except ET.ParseError as e:
        meta["truncated"], meta["error"] = True, clean(e, 120)
        if root is None:
            meta["kind"] = "not-xml"


# ================================================== roles: signals ====

class View:
    """What a rule can look at: only open ports count."""
    def __init__(self, rec):
        self.rec = rec
        self.open = {k: p for k, p in rec["ports"].items() if not p["closed_on"]}


def _rx(pattern, cs=False):
    return re.compile(pattern, 0 if cs else re.I)


def _snip(s, n=70):
    s = clean(s, 400)
    return s if len(s) <= n else s[: n - 3] + "..."


def _line_of(text, m):
    start = text.rfind("\n", 0, m.start()) + 1
    end = text.find("\n", m.end())
    return text[start: end if end != -1 else len(text)]


def iter_scripts(v):
    for k, p in sorted_ports(v.open):
        for sid, txt in sorted(p["scripts"].items()):
            yield k, sid, txt, p["last_seen"]
    for sid, txt in sorted(v.rec["hostscripts"].items()):
        yield "host", sid, txt, v.rec["last_seen"]


def _prod(p):
    return " ".join(x for x in (p["product"], p["version"], f"({p['extra']})" if p["extra"] else "") if x)


def P(*nums, proto="tcp"):
    """Any of these ports open."""
    keys = [f"{n}/{proto}" for n in nums]

    def sig(v):
        return next((f"{k} open" for k in keys if k in v.open), None)
    return sig


def ALL(*sigs):
    """Every signal must match."""
    def sig(v):
        ev = []
        for s in sigs:
            e = s(v)
            if not e:
                return None
            ev.append(e)
        if all(e.endswith(" open") for e in ev):
            return " + ".join(e[:-5] for e in ev) + " open"
        return " + ".join(ev)
    return sig


def SVC(pattern):
    """Service name, only when -sV actually probed it (not the port-number guess)."""
    rx = _rx(pattern)

    def sig(v):
        for k, p in sorted_ports(v.open):
            if p["method"] == "probed" and rx.search(p["service"]):
                return f"{k} service {p['service']}"
    return sig


def PROD(pattern, cs=False):
    """-sV product, version or extra info."""
    rx = _rx(pattern, cs)

    def sig(v):
        for k, p in sorted_ports(v.open):
            t = _prod(p)
            if t and rx.search(t):
                return f"{k} {_snip(t)}"
    return sig


def SCRIPT(id_pattern, pattern, cs=False):
    """NSE script output (port or host scripts)."""
    idrx, rx = re.compile(id_pattern), _rx(pattern, cs)

    def sig(v):
        for where, sid, txt, _ in iter_scripts(v):
            if idrx.search(sid):
                m = rx.search(txt)
                if m:
                    return f"{where} {sid}: {_snip(_line_of(txt, m))}"
    return sig


# Scripts whose output is the service describing itself.
_SELF_SCRIPTS = (r"^(http-title|banner|http-server-header|http-generator|http-favicon|"
                 r"snmp-sysdescr|vmware-version|upnp-info|sip-methods|fingerprint-strings|"
                 r"ftp-syst|tn3270-screen|rtsp-methods)$")


def TEXT(pattern, cs=False):
    """The service names itself: -sV product or self-describing script output."""
    a, b = PROD(pattern, cs), SCRIPT(_SELF_SCRIPTS, pattern, cs)

    def sig(v):
        return a(v) or b(v)
    return sig


def CERT(pattern, cs=False):
    return SCRIPT(r"^ssl-cert$", pattern, cs)


def NAME(pattern, cs=False):
    """Hostname match. Names are chosen by people, so this is only ever a maybe."""
    rx = _rx(pattern, cs)

    def sig(v):
        for n in [v.rec["hostname"]] + v.rec["names"]:
            if n and rx.search(n):
                return f"hostname {n}"
    return sig


def DEVTYPE(pattern):
    rx = _rx(pattern)

    def sig(v):
        for t in v.rec["devtypes"]:
            if rx.search(t):
                return f"nmap device type {t}"
        for k, p in sorted_ports(v.open):
            if p["devtype"] and rx.search(p["devtype"]):
                return f"{k} device type {p['devtype']}"
    return sig


def VENDOR(pattern):
    rx = _rx(pattern)

    def sig(v):
        if v.rec["vendor"] and rx.search(v.rec["vendor"]):
            return f"MAC vendor {v.rec['vendor']}"
    return sig


# ip -> number of scanned hosts whose traceroute passes through it (set in main)
GATEWAYS = {}


def GW():
    """A hop in other hosts' traceroute is a router (or L3 switch / firewall) for sure."""
    def sig(v):
        n = GATEWAYS.get(v.rec["ip"], 0)
        if n:
            return f"router on the traceroute path to {n} scanned host{'s' if n > 1 else ''}"
    return sig


def OSANY(pattern):
    """OS string from any source, even a weak guess. Only for maybe signals."""
    rx = _rx(pattern)

    def sig(v):
        if v.rec["os"] and rx.search(v.rec["os"]):
            return f"OS guess {v.rec['os']} ({v.rec['os_src']} {v.rec['os_acc']}%)"
    return sig


def OSRX(pattern):
    """OS string, only from a strong source (not a low accuracy guess)."""
    rx = _rx(pattern)

    def sig(v):
        if v.rec["os"] and v.rec["os_str"] >= STR_FP_HIGH and rx.search(v.rec["os"]):
            return f"OS {v.rec['os']} ({v.rec['os_src']})"
    return sig


def rule(role, label, group, text=None, cs=False, confirm=(), maybe=(), caution=""):
    """
    confirm: any match makes the role confirmed.
    maybe:   used only when nothing confirms; shown with a ? everywhere.
    text:    pattern the service must state about itself (confirm); the same
             pattern in a certificate or hostname only gives a maybe.
    """
    c, m = list(confirm), list(maybe)
    if text:
        c.insert(0, TEXT(text, cs))
        m += [CERT(text, cs), NAME(text, cs)]
    return {"role": role, "label": label, "group": group, "confirm": c, "maybe": m,
            "caution": caution}


# ==================================================== roles: rules ====
# Add your own rules here. Order inside a group is the display order.

GROUPS = ["Identity", "Virtualization and hardware", "Banking and payments", "Databases",
          "Management and backup", "Middleware and apps", "Containers",
          "Network and security", "Storage", "Fragile and OT"]

RULES = [
    # Identity
    rule("dc", "Domain Controller", "Identity",
         confirm=[ALL(P(88), P(389), P(445)),
                  ALL(P(88), PROD(r"Active Directory LDAP")),
                  SCRIPT(r"^ldap-rootdse$", r"domainControllerFunctionality|isGlobalCatalogReady")],
         maybe=[P(88), P(3268, 3269), NAME(r"^(dc|pdc|adc|ad)\d*([.-]|$)")]),
    rule("adcs", "AD Certificate Services", "Identity",
         text=r"Active Directory Certificate Services|/certsrv"),
    rule("adfs", "AD FS", "Identity", text=r"\bAD ?FS\b|/adfs/"),
    rule("pam", "Privileged access (PAM)", "Identity",
         text=r"CyberArk|PasswordVault|Password Vault Web Access|BeyondTrust|Thycotic|"
              r"Secret Server|Delinea|Password Manager Pro|PAM360|Wallix|senhasegura",
         maybe=[P(1858)]),
    rule("radius", "RADIUS / NPS", "Identity", confirm=[SVC(r"^radius")],
         maybe=[P(1812, 1645, proto="udp")]),

    # Virtualization and hardware
    rule("esxi", "VMware ESXi", "Virtualization and hardware", text=r"VMware ESXi",
         confirm=[SCRIPT(r"^vmware-version$", r"ESXi|embeddedEsx"), OSRX(r"ESXi")],
         maybe=[P(902)]),
    rule("vcenter", "VMware vCenter", "Virtualization and hardware",
         text=r"vCenter|ID_VC_Welcome|vSphere Client",
         confirm=[SCRIPT(r"^vmware-version$", r"VirtualCenter|vCenter|\bvpx\b")],
         maybe=[P(5480), SCRIPT(r"^http-title$", r"VMware vSphere")]),
    rule("hyper-v", "Hyper-V host", "Virtualization and hardware", maybe=[P(2179)]),
    rule("proxmox", "Proxmox VE", "Virtualization and hardware", text=r"Proxmox", maybe=[P(8006)]),
    rule("nutanix", "Nutanix", "Virtualization and hardware",
         text=r"Nutanix|Prism Central|Prism Element", maybe=[P(9440)]),
    rule("xen", "Citrix Hypervisor / XenServer", "Virtualization and hardware",
         text=r"XenServer|Citrix Hypervisor|XCP-ng"),
    rule("bmc", "Server management (iLO / iDRAC / IPMI)", "Virtualization and hardware",
         text=r"Integrated Lights-Out|\biLO ?[0-9]?\b|iDRAC|Dell Remote Access|"
              r"Integrated Management Module|\bIMM2?\b|XClarity|MegaRAC|Supermicro|"
              r"\bIPMI\b|Cisco Integrated Management Controller|\bCIMC\b|\biBMC\b",
         confirm=[SCRIPT(r"^ipmi-version$", r"Version")],
         maybe=[P(623, proto="udp"), P(17988, 17990)], caution="high"),

    # Banking and payments
    rule("swift", "SWIFT", "Banking and payments", cs=True,
         text=r"\bSWIFT(Net)?\b|Alliance (Access|Gateway|Web Platform|Messaging Hub|Lite2)",
         caution="critical"),
    rule("core-banking", "Core banking", "Banking and payments",
         text=r"Temenos|\bT24\b|Finacle|FLEXCUBE|Oracle Banking|\bBaNCS\b|Fiserv|Jack Henry|"
              r"Symitar|Finastra|Fusion Essence|Misys|\biMAL\b|Path Solutions|ICS BANKS|"
              r"BankFusion|Mambu|Silverlake",
         caution="high"),
    rule("card-payments", "Card / payment switch", "Banking and payments",
         text=r"BASE24|Postilion|Euronet|CardPro|\bWay4\b|OpenWay|SmartVista|TranzWare|"
              r"Compass Plus|PowerCARD",
         caution="critical"),
    rule("hsm", "HSM", "Banking and payments",
         text=r"payShield|Thales e-Security|nShield|SafeNet|Luna (SA|Network HSM)|Utimaco|"
              r"Futurex|\bHSM\b",
         maybe=[P(1500, 1501)], caution="critical"),
    rule("atm", "ATM / ATM management", "Banking and payments",
         text=r"APTRA|Vynamic|ProView|ProCash|Agilis|Diebold|Wincor|Nixdorf|Hyosung|"
              r"GRG Banking|Kalignite",
         maybe=[VENDOR(r"NCR|Diebold|Wincor|Hyosung|GRG")], caution="critical"),
    rule("ibm-i", "IBM i (AS/400)", "Banking and payments",
         text=r"\bOS/400\b|\bAS/?400\b|\bIBM i\b|\biSeries\b|\bi5/OS\b",
         confirm=[OSRX(r"OS/400|IBM i\b")],
         maybe=[P(449), P(8470, 8471, 8472, 8473, 8474, 8475, 8476)], caution="high"),
    rule("mainframe", "IBM mainframe (z/OS)", "Banking and payments",
         text=r"\bz/OS\b|TN3270|\bMVS\b|\bVTAM\b|\bCICS\b",
         confirm=[SCRIPT(r"^tn3270-screen$", r".")], caution="high"),
    rule("ibm-mq", "IBM MQ", "Banking and payments",
         text=r"WebSphere MQ|IBM MQ\b|MQSeries", confirm=[SVC(r"ibm-mqseries")],
         maybe=[P(1414)]),
    rule("pos", "POS terminal", "Banking and payments",
         text=r"Verifone|Ingenico|PAX Technology", maybe=[VENDOR(r"Verifone|Ingenico|PAX")],
         caution="high"),

    # Databases
    rule("mssql", "Microsoft SQL Server", "Databases", text=r"Microsoft SQL Server",
         confirm=[SVC(r"^ms-sql-s$"), SCRIPT(r"^ms-sql-(info|ntlm-info)$", r".")],
         maybe=[P(1433)]),
    rule("oracle-db", "Oracle Database", "Databases", text=r"Oracle TNS",
         confirm=[SVC(r"^oracle(-tns)?$")], maybe=[P(1521, 1522)]),
    rule("db2", "IBM Db2", "Databases", text=r"\bDB2\b|IBM Db2", confirm=[SVC(r"ibm-db2|drda")]),
    rule("mysql", "MySQL / MariaDB", "Databases", text=r"MySQL|MariaDB",
         confirm=[SVC(r"^mysql$")], maybe=[P(3306)]),
    rule("postgres", "PostgreSQL", "Databases", text=r"PostgreSQL",
         confirm=[SVC(r"^postgresql$")], maybe=[P(5432)]),
    rule("sybase", "SAP ASE (Sybase)", "Databases", text=r"Sybase|Adaptive Server Enterprise"),
    rule("mongodb", "MongoDB", "Databases", text=r"MongoDB", confirm=[SVC(r"^mongod")],
         maybe=[P(27017)]),
    rule("redis", "Redis", "Databases", text=r"\bRedis\b", confirm=[SVC(r"^redis$")],
         maybe=[P(6379)]),
    rule("elasticsearch", "Elasticsearch / OpenSearch", "Databases",
         text=r"Elasticsearch|OpenSearch", maybe=[P(9200)]),

    # Management and backup
    rule("sccm", "SCCM / MECM", "Management and backup",
         text=r"Configuration Manager|System Center|\bSCCM\b|\bMECM\b", maybe=[P(10123)]),
    rule("wsus", "WSUS", "Management and backup",
         text=r"\bWSUS\b|Windows Server Update Services", maybe=[P(8530, 8531)]),
    rule("veeam", "Veeam Backup", "Management and backup", text=r"Veeam",
         maybe=[P(9392, 9401, 10006)]),
    rule("commvault", "Commvault", "Management and backup", text=r"Commvault|CommServe",
         maybe=[P(8400, 8403)]),
    rule("netbackup", "Veritas NetBackup / Backup Exec", "Management and backup",
         text=r"NetBackup|Backup Exec|Veritas", confirm=[SVC(r"^(vnetd|bpcd|bprd)$")],
         maybe=[P(1556, 13724)]),
    rule("monitoring", "Monitoring", "Management and backup",
         text=r"Zabbix|\bPRTG\b|Nagios|Icinga|SolarWinds|\bOrion\b|Centreon|LibreNMS|"
              r"Observium|Checkmk|Check_MK|Grafana|Prometheus|WhatsUp Gold",
         maybe=[P(10050, 10051)]),
    rule("siem", "SIEM / logging", "Management and backup",
         text=r"Splunk|QRadar|ArcSight|Kibana|Graylog|Wazuh|LogRhythm|FortiSIEM",
         maybe=[P(8089)]),
    rule("admin-tools", "Admin / remote management", "Management and backup",
         text=r"ManageEngine|ServiceDesk Plus|ADManager|ADSelfService|Endpoint Central|"
              r"Desktop Central|Ivanti|LANDesk|Kaseya|ConnectWise|ScreenConnect|Dameware|"
              r"NinjaRMM|N-able|Lansweeper|\bGLPI\b|Tanium|BigFix"),
    rule("ci-devops", "CI/CD, code and artifacts", "Management and backup",
         text=r"Jenkins|GitLab|Gitea|Bitbucket|TeamCity|Bamboo|Azure DevOps|SonarQube|"
              r"Nexus Repository|Sonatype|Artifactory|JFrog|\bHarbor\b|\bAWX\b|"
              r"Ansible (Tower|Automation)|Rundeck|Octopus Deploy|Argo ?CD"),

    # Middleware and apps
    rule("exchange", "Microsoft Exchange", "Middleware and apps",
         text=r"Outlook Web App|/owa/|Microsoft Exchange|\bOutlook\b"),
    rule("sharepoint", "SharePoint", "Middleware and apps", text=r"SharePoint"),
    rule("collab", "Jira / Confluence", "Middleware and apps",
         text=r"\bJira\b|Confluence|Atlassian"),
    rule("citrix", "Citrix", "Middleware and apps",
         text=r"Citrix|NetScaler|StoreFront|XenApp|XenDesktop",
         confirm=[SVC(r"^citrix-ica$")], maybe=[P(1494, 2598)]),
    rule("rd-gateway", "RD Gateway / RD Web", "Middleware and apps",
         text=r"RD Web Access|/RDWeb|Remote Desktop Gateway|\bRD Gateway\b"),
    rule("sap", "SAP", "Middleware and apps", cs=True,
         text=r"\bSAP\b|NetWeaver|SAProuter|\bHANA\b", maybe=[P(3299)]),
    rule("weblogic", "Oracle WebLogic", "Middleware and apps", text=r"WebLogic",
         confirm=[SCRIPT(r"^weblogic-t3-info$", r".")], maybe=[P(7001, 7002)]),
    rule("websphere", "IBM WebSphere", "Middleware and apps",
         text=r"WebSphere Application Server|WebSphere Liberty", maybe=[P(9060, 9043)]),
    rule("jboss", "JBoss / WildFly", "Middleware and apps", text=r"JBoss|WildFly"),
    rule("tomcat", "Apache Tomcat", "Middleware and apps", text=r"Tomcat|Apache-Coyote"),
    rule("oracle-apps", "Oracle applications", "Middleware and apps",
         text=r"Oracle E-Business|Oracle HTTP Server|Oracle Application Server|PeopleSoft|"
              r"JD Edwards|Siebel|Oracle Fusion Middleware"),

    # Containers
    rule("kubernetes", "Kubernetes", "Containers",
         text=r"kubernetes|kube-apiserver|kubelet", maybe=[P(6443), P(10250)]),
    rule("docker-api", "Docker API", "Containers", text=r"\bDocker\b",
         confirm=[SVC(r"^docker$"), SCRIPT(r"^docker-version$", r".")], maybe=[P(2375, 2376)]),
    rule("etcd", "etcd", "Containers", text=r"\betcd\b", maybe=[P(2379, 2380)]),
    rule("container-mgmt", "Container management", "Containers",
         text=r"OpenShift|Rancher|Portainer|Tanzu"),

    # Network and security
    rule("firewall", "Firewall", "Network and security",
         text=r"FortiGate|FortiOS|Fortinet|Palo Alto Networks|PAN-OS|Check Point|\bGaia\b|"
              r"SonicWall|SonicOS|Sophos|WatchGuard|pfSense|OPNsense|Cisco ASA|"
              r"Adaptive Security Appliance|Firepower|Barracuda|Forcepoint|Stormshield|"
              r"Juniper SRX",
         confirm=[DEVTYPE(r"firewall")], caution="high"),
    rule("vpn", "VPN gateway", "Network and security",
         text=r"GlobalProtect|Pulse Secure|Pulse Connect|Ivanti Connect Secure|AnyConnect|"
              r"SSL ?VPN|FortiClient|OpenVPN Access Server|\bVPN\b",
         caution="high"),
    rule("load-balancer", "Load balancer / ADC", "Network and security",
         text=r"BIG-IP|F5 Networks|NetScaler|Kemp|A10 Networks|Radware|Alteon",
         caution="high"),
    rule("network-device", "Router / switch / wireless", "Network and security",
         text=r"Cisco IOS|IOS[- ]XE|IOS[- ]XR|NX-OS|Catalyst|RouterOS|MikroTik|JUNOS|"
              r"Juniper Networks|ProCurve|ArubaOS|Aruba Networks|Comware|Huawei VRP|"
              r"Versatile Routing Platform|ZyXEL|EdgeOS|EdgeSwitch|UniFi|Ubiquiti|RUCKUS|"
              r"ExtremeXOS|Extreme Networks|Brocade|Allied Telesis|Netgear|TP-LINK|D-Link|"
              r"Meraki",
         confirm=[GW(), OSRX(r"Cisco|RouterOS|JUNOS|NX-OS|IOS XE"),
                  DEVTYPE(r"router|switch|WAP|bridge|hub")],
         maybe=[OSANY(r"Cisco|IOS XE|NX-OS|RouterOS|MikroTik|JUNOS|Juniper|ProCurve|Aruba|"
                      r"Comware|Huawei|ZyXEL|EdgeOS|Ubiquiti|Brocade|Extreme|Netgear|TP-LINK|D-Link|"
                      r"switch|router"),
                VENDOR(r"Cisco|Juniper|Aruba|MikroTik|Routerboard|Ubiquiti|Extreme|"
                       r"Brocade|Fortinet|Ruckus|Netgear|TP-LINK|D-Link|Zyxel|Allied Telesis"),
                SVC(r"^smart-install$"), P(4786)],
         caution="high"),
    rule("nac", "NAC", "Network and security",
         text=r"ClearPass|Cisco ISE|Identity Services Engine|FortiNAC|Forescout|PacketFence",
         caution="high"),
    rule("mail-gateway", "Mail security gateway", "Network and security",
         text=r"IronPort|Secure Email Gateway|Proofpoint|Mimecast|FortiMail"),
    rule("proxy", "Web proxy", "Network and security",
         text=r"Squid|Blue ?Coat|ProxySG|Zscaler|Websense|McAfee Web Gateway|Skyhigh",
         maybe=[P(3128)]),
    rule("ddi", "DNS / DHCP / IPAM appliance", "Network and security",
         text=r"Infoblox|BlueCat|EfficientIP"),

    # Storage
    rule("storage", "Storage / NAS / backup appliance", "Storage",
         text=r"Synology|DiskStation|QNAP|NetApp|ONTAP|OnCommand|Unisphere|PowerStore|"
              r"PowerScale|Isilon|PowerVault|EqualLogic|TrueNAS|FreeNAS|3PAR|HPE Primera|"
              r"Nimble|Pure Storage|Purity|Hitachi Vantara|StoreOnce|Data Domain|Storwize|"
              r"FlashSystem",
         caution="high"),

    # Fragile and OT
    rule("ics", "OT / ICS", "Fragile and OT",
         text=r"SIMATIC|Siemens S7|Schneider Electric|Modicon|Rockwell|Allen-Bradley|Niagara|"
              r"Tridium|Johnson Controls|Metasys|\bMoxa\b|\bWago\b|Beckhoff|CODESYS|Red Lion|"
              r"\bOmron\b|Mitsubishi Electric|Yokogawa",
         confirm=[SCRIPT(r"^(modbus-discover|s7-info|enip-info|bacnet-info|fox-info|"
                         r"codesys-v2-discover|omron-info|pcworx-info|proconos-info|"
                         r"dnp3-info|iec-identify)$", r".")],
         maybe=[P(502), P(102), P(44818), P(47808, proto="udp"), P(20000), P(2404),
                P(1911, 4911), P(789), P(9600), P(1962), P(2455), P(18245, 18246)],
         caution="critical"),
    rule("medical", "Medical / DICOM", "Fragile and OT",
         text=r"DICOM|\bPACS\b|IntelliSpace|GE Healthcare|Healthineers|Carestream",
         confirm=[SVC(r"^dicom$")], maybe=[P(104), P(11112)], caution="critical"),
    rule("printer", "Printer", "Fragile and OT",
         text=r"JetDirect|LaserJet|OfficeJet|Xerox|RICOH|Kyocera|\bCanon\b|Lexmark|Konica|"
              r"bizhub|Sharp MX|Epson|Toshiba TEC|e-STUDIO|\bZebra\b",
         confirm=[DEVTYPE(r"printer|print server"), SVC(r"^(jetdirect|ipp|printer)$")],
         maybe=[P(9100), P(515), P(631)], caution="high"),
    rule("ups", "UPS / PDU / power", "Fragile and OT",
         text=r"PowerChute|Network Management Card|\bAPC\b|American Power Conversion|"
              r"\bEaton\b|Liebert|Vertiv|Riello|NetAgent|\bUPS\b|\bPDU\b|ServerTech|Raritan",
         maybe=[VENDOR(r"American Power Conversion|Eaton|Vertiv|Liebert")], caution="high"),
    rule("camera", "Camera / NVR", "Fragile and OT",
         text=r"Hikvision|Dahua|Axis Communications|\bAXIS [A-Z]?[0-9]|Hanwha|Samsung Techwin|"
              r"Uniview|Bosch Security|Avigilon|Milestone|Genetec|NETSurveillance|\bDVR\b|"
              r"\bNVR\b|IP Camera|IPCam|webcam|Vivotek|Mobotix|Reolink",
         confirm=[DEVTYPE(r"webcam"),
                  VENDOR(r"Hikvision|Dahua|Axis Communications|Hanwha|Uniview|Vivotek|Mobotix|Avigilon")],
         maybe=[SVC(r"^rtsp$"), P(554), P(37777)], caution="high"),
    rule("voip", "VoIP / phones / PBX", "Fragile and OT",
         text=r"Asterisk|FreePBX|Cisco Unified Communications|\bCUCM\b|Call ?Manager|Avaya|"
              r"\b3CX\b|Yealink|Grandstream|Polycom|Mitel|OmniPCX|\bSnom\b|Fanvil|Issabel|"
              r"Elastix|Cisco IP Phone",
         confirm=[SVC(r"^sip$")], maybe=[P(5060, proto="udp"), P(5060, 5061)],
         caution="high"),
    rule("physical-security", "Access control / building", "Fragile and OT",
         text=r"Lenel|OnGuard|\bHID\b|Gallagher|Paxton|ZKTeco|Suprema|Synergis|C-CURE|"
              r"\bAMAG\b|Pro-Watch",
         caution="high"),
]


def classify(rec):
    v, out = View(rec), []
    for r in RULES:
        ev = [e for e in (s(v) for s in r["confirm"]) if e]
        conf = "confirmed"
        if not ev:
            ev = [e for e in (s(v) for s in r["maybe"]) if e]
            conf = "maybe"
        if ev:
            uniq = list(dict.fromkeys(ev))[:3]
            out.append({"role": r["role"], "label": r["label"], "group": r["group"],
                        "caution": r["caution"], "confidence": conf, "evidence": uniq})
    return out


def caution_of(roles, rec=None):
    """Fragile device classes. A maybe still counts (safe side), marked with ?"""
    level, why = "", []
    for r in roles:
        if r["caution"]:
            if CAUTION_RANK[r["caution"]] > CAUTION_RANK[level]:
                level = r["caution"]
            why.append(r["label"] + ("?" if r["confidence"] == "maybe" else ""))
    eol = os_eol(rec) if rec else None
    if eol and eol["legacy"]:
        level = level or "high"
        why.append(f"Legacy {eol['name']}" + ("" if eol["sure"] else "?"))
    return level, why


def role_list(roles):
    return ", ".join(r["role"] + ("?" if r["confidence"] == "maybe" else "") for r in roles)


# ========================================================== findings ====

# (regex on the OS string, name, end of support year, legacy = fragile old-era Windows)
EOL_OS = [
    (r"Windows NT", "Windows NT", "2004", True),
    (r"Windows 2000", "Windows 2000", "2010", True),
    (r"Windows XP", "Windows XP", "2014", True),
    (r"Windows (Server )?(\(R\) )?2003", "Windows Server 2003", "2015", True),
    (r"Windows Vista", "Windows Vista", "2017", False),
    (r"Windows 7\b", "Windows 7", "2020", False),
    (r"Windows (Server )?(\(R\) )?2008", "Windows Server 2008 / 2008 R2", "2020", False),
    (r"Windows 8\.1\b", "Windows 8.1", "2023", False),
    (r"Windows 8\b(?!\.\d)", "Windows 8", "2016", False),
    (r"Windows (Server )?(\(R\) )?2012", "Windows Server 2012 / 2012 R2", "2023", False),
    (r"Windows 10\b", "Windows 10", "2025", False),
]

# Outdated software from -sV product/version and HTTP headers: (regex, what it means)
EOL_SOFTWARE = [
    (r"Apache(?: httpd)?[ /](?:1\.|2\.[02]\.)\d", "Apache httpd 2.2 or older (end of life)"),
    (r"IIS(?: httpd)?[ /](?:[1-7]|8)\.\d", "Microsoft IIS 8.5 or older (Windows 2012 era or older)"),
    (r"PHP[ /](?:[3-7]\.|8\.[01]\b)", "PHP 8.1 or older (end of life)"),
    (r"OpenSSL/(?:0\.|1\.)", "OpenSSL 1.1.1 or older (end of life)"),
    (r"Tomcat[ /](?:[3-7]\.|8\.[05]\.)", "Apache Tomcat 8.5 or older (end of life)"),
    (r"Microsoft SQL Server (?:2000|2005|2008|2012|2014)\b", "Microsoft SQL Server 2014 or older (end of support)"),
    (r"Samba (?:smbd )?[1-3]\.[0-9X]+(?! - 4)", "Samba 3.x or older (end of life)"),
    (r"OpenSSH[ _][1-6]\.", "OpenSSH 6.x or older (released 2015 or earlier)"),
    (r"vsftpd 2\.3\.4\b", "vsftpd 2.3.4 (a release known to have shipped with a backdoor)"),
]


def os_eol(rec):
    """End of support OS, only from a strong source (self reported or fingerprint >= 95%)."""
    name = rec["os"]
    if not name or rec["os_str"] < STR_FP_HIGH or " or " in name:
        return None
    for rx, label, year, legacy in EOL_OS:
        if re.search(rx, name, re.I):
            if label == "Windows 10" and re.search(r"LTS[BC]", name):
                return None  # LTSC editions are still supported
            return {"name": label, "year": year, "legacy": legacy, "sure": rec["os_str"] >= STR_SELF}
    return None


def _vuln_title(text):
    lines = [ln.strip() for ln in text.split("\n")]
    for i, ln in enumerate(lines):
        if ln.endswith("VULNERABLE:"):
            nxt = next((x for x in lines[i + 1:] if x), "")
            return _snip(nxt, 90)
    return ""


def script_findings(sid, t, seen):
    f = []
    if re.search(r"State: VULNERABLE\b", t):
        f.append(f"Vulnerable: {_vuln_title(t) or sid} ({sid})")
    elif re.search(r"State: LIKELY VULNERABLE", t):
        f.append(f"Likely vulnerable: {_vuln_title(t) or sid} ({sid})")
    if sid == "smb2-security-mode" and re.search(r"not required", t, re.I):
        f.append("SMB signing not required")
    if sid == "smb-security-mode" and re.search(r"message_signing:\s*(disabled|supported)", t):
        f.append("SMB signing not required (SMBv1 negotiation)")
    if sid == "smb-protocols" and re.search(r"NT LM 0\.12|SMBv1", t):
        f.append("SMBv1 enabled")
    if sid == "ftp-anon" and "Anonymous FTP login allowed" in t:
        f.append("Anonymous FTP login allowed")
    if sid == "smb-enum-shares":
        acc = re.findall(r"Anonymous access:\s*(READ/WRITE|READ)", t)
        if acc:
            f.append(f"Anonymous SMB share access ({'READ/WRITE' if 'READ/WRITE' in acc else 'READ'})")
    if sid == "ssl-cert":
        m = re.search(r"Not valid after:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", t)
        if m and seen and m.group(1) < seen[:10]:
            f.append(f"TLS certificate expired {m.group(1)}")
    if sid == "sslv2" and "SSLv2 supported" in t:
        f.append("SSLv2 enabled")
    if sid == "ssl-enum-ciphers":
        if re.search(r"^\s*SSLv3:", t, re.M):
            f.append("SSLv3 enabled")
        m = re.search(r"least strength:\s*([C-F])\b", t)
        if m:
            f.append(f"Weak TLS configuration (ssl-enum-ciphers grade {m.group(1)})")
    if sid == "mysql-empty-password" and re.search(r"empty password", t, re.I):
        f.append("MySQL account with empty password")
    if sid == "ms-sql-empty-password" and re.search(r"Login Success", t, re.I):
        f.append("MSSQL login with empty password")
    if sid == "redis-info" and re.search(r"Version", t) and not re.search(r"auth", t, re.I):
        f.append("Redis answers without authentication")
    if sid == "mongodb-databases" and re.search(r"databases", t, re.I) and \
            not re.search(r"auth|unauthorized", t, re.I):
        f.append("MongoDB lists databases without authentication")
    if sid == "docker-version" and re.search(r"Version", t):
        f.append("Docker API answers without authentication")
    if sid == "nfs-showmount" and t.strip():
        f.append(f"NFS exports visible: {_snip(t.strip().split(chr(10))[0], 60)}")
    if sid in ("snmp-sysdescr", "snmp-info", "snmp-interfaces", "snmp-netstat",
               "snmp-processes", "snmp-win32-users", "snmp-win32-software") and t.strip():
        f.append("SNMP answers to the community nmap used (default: public)")
    if sid == "http-default-accounts" and re.search(r"\S+:\S*", t):
        f.append("Default web credentials accepted (http-default-accounts)")
    if sid == "vnc-info" and re.search(r"Security types:\s*\n\s*None", t):
        f.append("VNC without authentication")
    if sid == "x11-access" and "access is granted" in t:
        f.append("X11 server allows access")
    if sid == "http-title" and "Index of /" in t:
        f.append("Directory listing enabled")
    if sid == "http-git" and ".git" in t:
        f.append("Exposed .git repository")
    if sid == "tftp-enum" and t.strip():
        f.append("TFTP files readable")
    if sid == "http-methods" and re.search(r"Potentially risky methods:.*\b(PUT|DELETE)\b", t):
        f.append("HTTP PUT/DELETE allowed")
    return f


def findings(rec, roles=None):
    out, seen = [], set()
    for where, sid, txt, at in iter_scripts(View(rec)):
        for text in script_findings(sid, txt, at):
            key = text if text.startswith("SNMP") else (where, text)
            if key not in seen:
                seen.add(key)
                out.append((where, text))
    v = View(rec)
    eol = os_eol(rec)
    if eol:
        src = rec["os_src"] if eol["sure"] else f"fingerprint {rec['os_acc']}%, a guess"
        word = "End of support OS" if eol["sure"] else "Likely end of support OS"
        out.append(("os", f"{word}: {eol['name']}, unsupported since {eol['year']} ({src})"))
        n = eol["name"]
        if eol["legacy"] and "445/tcp" in v.open:
            out.append(("os", "Check: MS08-067 and MS17-010 (smb-vuln-ms17-010 is safe, "
                              "smb-vuln-ms08-067 can crash the host)"))
        elif re.search(r"Vista|Windows 7|2008", n) and "445/tcp" in v.open:
            out.append(("os", "Check: MS17-010 (smb-vuln-ms17-010)"))
        if re.search(r"XP|2003|Vista|Windows 7|2008", n) and "3389/tcp" in v.open:
            out.append(("os", "Check: BlueKeep CVE-2019-0708 on RDP (affects this OS family, not verified)"))
    if roles is None:
        roles = classify(rec)
    if any(r["confidence"] == "confirmed" and r["role"] in APPLIANCE_ROLES for r in roles):
        return out[:40]  # a device's web server is its firmware; the role says what it is
    if "4786/tcp" in v.open:
        out.append(("4786/tcp", "Cisco Smart Install open: the switch config can often be read or "
                                "replaced, and old IOS may crash under probes"))
    for k, p in sorted_ports(v.open):
        text = " ".join((_prod(p), p["scripts"].get("http-server-header", ""),
                         p["scripts"].get("http-headers", ""), p["scripts"].get("banner", "")))
        for rx, label in EOL_SOFTWARE:
            m = re.search(rx, text, re.I)
            if m:
                out.append((k, f"Outdated: {label} ({_snip(_line_of(text, m), 50)})"))
    return out[:40]


# ========================================================= web stack ====
# What a web service is built with, from what nmap saw: Server and other headers,
# cookie names, generator meta tag, title, robots.txt and auth. Nmap does not run
# JavaScript, so front end frameworks (React, Vue, Angular) are mostly invisible.

def W(name, tag, *rules):
    return {"name": name, "tag": tag, "rules": [(src, re.compile(rx, re.I)) for src, rx in rules]}


WEB_TECH = [
    # servers
    W("nginx", "nginx", ("hdr", r"\bnginx(?:[/ ](?P<v>\d[\d.]*))?")),
    W("OpenResty", "openresty", ("hdr", r"openresty(?:[/ ](?P<v>\d[\d.]*))?")),
    W("Apache httpd", "apache", ("hdr", r"Server: Apache(?:/(?P<v>\d[\d.]*))?(?![-\w])"),
      ("hdr", r"Product: Apache httpd(?: (?P<v>\d[\d.]*))?")),
    W("Microsoft IIS", "iis", ("hdr", r"Microsoft-IIS(?:/(?P<v>\d[\d.]*))?"),
      ("hdr", r"Product: Microsoft IIS httpd(?: (?P<v>\d[\d.]*))?")),
    W("Microsoft HTTPAPI (http.sys: WinRM, WSUS, ADFS...)", "httpapi",
      ("hdr", r"Microsoft-HTTPAPI(?:/(?P<v>\d[\d.]*))?"),
      ("hdr", r"Product: Microsoft HTTPAPI httpd(?: (?P<v>\d[\d.]*))?")),
    W("LiteSpeed", "litespeed", ("hdr", r"LiteSpeed")),
    W("Caddy", "caddy", ("hdr", r"\bCaddy\b")),
    W("lighttpd", "lighttpd", ("hdr", r"lighttpd(?:[/ ](?P<v>\d[\d.]*))?")),
    W("Apache Tomcat", "tomcat", ("hdr", r"Product: Apache Tomcat(?: (?P<v>\d[\d.]*))?"),
      ("title", r"Apache Tomcat(?:/(?P<v>\d[\d.]*))?"), ("hdr", r"Apache-Coyote")),
    W("Jetty", "jetty", ("hdr", r"Jetty\(?(?P<v>\d[\w.\-]*)?")),
    W("Kestrel (.NET)", "kestrel", ("hdr", r"\bKestrel\b")),
    W("gunicorn (Python)", "gunicorn", ("hdr", r"gunicorn(?:[/ ](?P<v>\d[\d.]*))?")),
    W("uvicorn (Python)", "uvicorn", ("hdr", r"\buvicorn\b")),
    W("Werkzeug (Flask, Python)", "flask", ("hdr", r"Werkzeug(?:/| httpd )(?P<v>\d[\d.]*)|Werkzeug")),
    W("Python http.server", "python-http", ("hdr", r"SimpleHTTP|BaseHTTP")),
    W("Node.js", "nodejs", ("hdr", r"Product: Node\.js")),
    W("Envoy", "envoy", ("hdr", r"\benvoy\b")),
    # languages and runtimes
    W("PHP", "php", ("hdr", r"PHP/(?P<v>\d[\d.]*)"), ("cookie", r"\bPHPSESSID\b")),
    W("ASP.NET", "aspnet", ("hdr", r"X-AspNet-Version:\s*(?P<v>[\d.]+)"),
      ("hdr", r"X-Powered-By:\s*ASP\.NET"),
      ("cookie", r"ASP\.NET_SessionId|ASPSESSIONID|\.ASPXAUTH|__RequestVerificationToken")),
    W("ASP.NET MVC", "aspnet-mvc", ("hdr", r"X-AspNetMvc-Version:\s*(?P<v>[\d.]+)")),
    W("Java servlet", "java", ("cookie", r"\bJSESSIONID\b"), ("hdr", r"Servlet/(?P<v>[\d.]+)|\bJSP/")),
    W("Python", "python", ("hdr", r"\bPython/(?P<v>\d[\d.]*)")),
    W("Ruby (Passenger)", "ruby", ("hdr", r"Phusion Passenger(?: (?P<v>\d[\d.]*))?")),
    # frameworks
    W("Laravel", "laravel", ("cookie", r"\blaravel_session\b")),
    W("CodeIgniter", "codeigniter", ("cookie", r"\bci_session\b")),
    W("CakePHP", "cakephp", ("cookie", r"\bCAKEPHP\b")),
    W("Symfony", "symfony", ("hdr", r"X-Debug-Token"), ("cookie", r"\bsf_redirect\b")),
    W("Express (Node.js)", "express", ("hdr", r"X-Powered-By:\s*Express"),
      ("cookie", r"\bconnect\.sid\b"), ("hdr", r"Product: Node\.js Express")),
    W("Next.js", "nextjs", ("hdr", r"X-Powered-By:\s*Next\.js(?: (?P<v>[\d.]+))?")),
    W("Django", "django", ("cookie", r"\bcsrftoken\b"), ("title", r"\bDjango\b")),
    W("Spring Boot", "spring", ("title", r"Whitelabel Error Page")),
    # CMS
    W("WordPress", "wordpress", ("gen", r"WordPress ?(?P<v>\d[\d.]*)?"), ("robots", r"/wp-admin"),
      ("cookie", r"wordpress_|wp-settings")),
    W("Drupal", "drupal", ("gen", r"Drupal ?(?P<v>\d+)?")),
    W("Joomla", "joomla", ("gen", r"Joomla!? ?(?P<v>\d[\d.]*)?")),
    W("Moodle", "moodle", ("cookie", r"MoodleSession")),
    # in front of the app
    W("F5 BIG-IP in front", "f5", ("cookie", r"BIGipServer")),
    W("Citrix NetScaler in front", "netscaler", ("cookie", r"\bNSC_")),
    # how it authenticates
    W("NTLM / Negotiate auth", "ntlm-auth", ("auth", r"\bNTLM\b|\bNegotiate\b")),
    W("Basic auth", "basic-auth", ("auth", r"Basic realm=(?P<v>[^\n]{0,40})")),
    W("WebDAV", "webdav", ("webdav", r"WebDAV|\bDAV\b")),
]

_WEB_SRC = {"hdr": "headers", "cookie": "cookie", "gen": "generator", "title": "title",
            "robots": "robots.txt", "auth": "auth", "webdav": "webdav"}

# Confirmed roles that make a host an appliance: its web UI is just the device's UI.
APPLIANCE_ROLES = {"bmc", "printer", "camera", "ups", "voip", "ics", "medical", "physical-security",
                   "network-device", "firewall", "load-balancer", "storage", "nac", "atm", "pos",
                   "hsm", "esxi", "vcenter", "proxmox", "nutanix", "xen"}


def is_web(p):
    return bool(re.search(r"http", p["service"])) or any(s.startswith("http-") for s in p["scripts"])


def web_stack(p):
    s = p["scripts"]
    headers = s.get("http-headers", "")
    hdr = "\n".join(x for x in (
        f"Server: {_first_line(s['http-server-header'])}" if s.get("http-server-header") else "",
        f"Product: {_prod(p)}" if p["product"] else "", headers) if x)
    texts = {
        "hdr": hdr,
        "cookie": s.get("http-cookie-flags", "") + "\n" + "\n".join(
            re.findall(r"(?im)^\s*Set-Cookie:\s*([^=\n]+)", headers)),
        "gen": s.get("http-generator", "") + "\n" + "\n".join(
            re.findall(r"(?im)^\s*X-Generator:\s*(.+)$", headers)),
        "title": s.get("http-title", ""),
        "robots": s.get("http-robots.txt", ""),
        "auth": s.get("http-auth", "") + ("\nNTLM" if "http-ntlm-info" in s else ""),
        "webdav": s.get("http-webdav-scan", ""),
    }
    found = {}
    for t in WEB_TECH:
        for src, rx in t["rules"]:
            m = rx.search(texts[src])
            if not m:
                continue
            ver = (m.groupdict().get("v") or "").strip()
            if t["name"] not in found or (ver and not found[t["name"]]["version"]):
                ev = "NTLM info script" if src == "auth" and m.group(0) == "NTLM" and "http-ntlm-info" in s \
                    else f"{_WEB_SRC[src]}: {_snip(_line_of(texts[src], m).strip(), 45)}"
                found[t["name"]] = {"name": t["name"], "tag": t["tag"], "version": clean(ver, 40),
                                    "evidence": ev}
    return list(found.values())


def host_web(rec, roles):
    """[(port, stack)] for web ports, or the appliance label when the host is a device."""
    dev = next((r["label"] for r in roles if r["confidence"] == "confirmed"
                and r["role"] in APPLIANCE_ROLES), None)
    if dev:
        return dev, []
    out = []
    for k, p in sorted_ports(View(rec).open):
        if is_web(p):
            out.append((k, web_stack(p)))
    return None, out


def stack_text(stack):
    return ", ".join(f"{t['name']} {t['version']}".strip() for t in stack)


# ============================================================= merge ====

def path_rank(p):
    return (sum(1 for h in p["hops"] if h != "*"), p["seen"])


def pick_gateway(paths):
    if not paths:
        return ""
    best = max(paths, key=path_rank)
    last = best["hops"][-1] if best["hops"] else ""
    return last if last != "*" else ""


def alive_rank(why):
    if not why:
        return 0
    if why.startswith(("open port", "MAC")):
        return 3
    if why.startswith(("OS", "host script")) or (why.startswith("discovery") and "firewall" not in why):
        return 2
    return 1


def merge(rec, ob, events):
    """Newest scan wins when it has the data. Empty never overwrites. Changes are logged."""
    ip, at = rec["ip"], ob["seen"]
    existed = bool(rec["last_seen"] or rec.pop("legacy", False))
    newer = at >= rec["last_seen"]

    def change(text, kind="CHANGE", mark="!"):
        if not existed:
            return
        entry = {"at": at, "text": clean(text, 240)}
        if entry in rec["changes"]:
            return
        rec["changes"] = sorted(rec["changes"] + [entry], key=lambda e: e["at"])[-100:]
        events.append((kind, ip, mark, entry["text"]))

    if ob["state"] == "down":
        if existed and at > rec["last_seen"] and rec["status"] != "down":
            rec["status"], rec["down_since"] = "down", at
            change("host did not respond (down in scan)", "DOWN", "-")
        return

    scan = {"file": ob["file"], "at": at}
    if scan not in rec["scans"]:
        rec["scans"] = sorted(rec["scans"] + [scan], key=lambda s: s["at"])[-20:]

    rec["alive"] = "yes"
    # keep the strongest reason seen: an open port beats a reset; ties keep the first
    if ob.get("alive_by") and alive_rank(ob["alive_by"]) > alive_rank(rec["alive_by"]):
        rec["alive_by"] = ob["alive_by"]
    if ob.get("hint"):
        rec["pending"] = not rec["ports"]
    else:
        rec["pending"] = False
    if rec["status"] == "down" and at > rec["down_since"]:
        rec["status"], rec["down_since"] = "up", ""
        change("host responds again", "UP", "+")
    rec["first_seen"] = dmin(rec["first_seen"], at)
    rec["last_seen"] = dmax(rec["last_seen"], at)

    for key, label in (("mac", "MAC"), ("vendor", ""), ("domain", "Domain"), ("build", "")):
        val = ob[key]
        if val and val != rec[key] and (newer or not rec[key]):
            if rec[key] and label:
                change(f"{label} {rec[key]} -> {val}")
            rec[key] = val

    for v6 in ob["ipv6"]:
        if v6 not in rec["ipv6"]:
            rec["ipv6"].append(v6)
    for n in ob["names"]:
        if n not in rec["names"]:
            rec["names"].append(n)
    rec["names"] = rec["names"][:10]
    hn = ob["hostname"]
    if hn and hn.lower() != rec["hostname"].lower() and (newer or not rec["hostname"]):
        if rec["hostname"]:
            change(f"hostname {rec['hostname']} -> {hn}")
        rec["hostname"] = hn

    c = ob["os"]
    if c:
        if not rec["os"] or (at >= rec["os_seen"] and c["str"] >= rec["os_str"]):
            if rec["os"] and rec["os"].lower() != c["name"].lower() and \
                    min(rec["os_str"], c["str"]) >= STR_OSTYPE:
                change(f"OS {rec['os']} -> {c['name']} ({c['src']})")
            rec.update(os=c["name"], os_src=c["src"], os_acc=c["acc"], os_str=c["str"], os_seen=at)
        elif at >= rec["os_seen"] and c["str"] >= STR_FP_HIGH and \
                os_family(c["name"]) != os_family(rec["os"]):
            change(f"{c['src']} now says {c['name']}, kept {rec['os']} ({rec['os_src']}); "
                   f"rescan with -sC to confirm")

    if ob["devtypes"] and newer:
        rec["devtypes"] = ob["devtypes"]

    paths = {p["via"]: p for p in rec["paths"]}
    for p in ob["paths"]:
        cur = paths.get(p["via"])
        if cur is None or path_rank(p) >= path_rank(cur):
            paths[p["via"]] = p
    rec["paths"] = sorted(paths.values(), key=lambda p: p["via"])[:8]

    for key, p in ob["ports"].items():
        cur = rec["ports"].get(key)
        if cur is None:
            p = dict(p, first_seen=at, last_seen=at, closed_on="")
            rec["ports"][key] = p
            change(f"port {key} open (new)" + (f": {_prod(p)}" if _prod(p) else ""), "CHANGE", "+")
            continue
        pnewer = at >= cur["last_seen"]
        if (p["product"] or p["version"]) and (pnewer or not (cur["product"] or cur["version"])):
            old, new = _prod(cur), _prod(p)
            if old and old != new:
                change(f"{key} {old} -> {new}")
            for k in ("product", "version", "extra", "ostype", "devtype", "cpe"):
                cur[k] = p[k]
        if p["service"] != "unknown" and (
                (p["method"] == "probed" and (pnewer or cur["method"] != "probed"))
                or cur["service"] == "unknown"):
            cur["service"], cur["method"], cur["tunnel"] = p["service"], p["method"], p["tunnel"]
        for sid, txt in p["scripts"].items():
            if pnewer or sid not in cur["scripts"]:
                cur["scripts"][sid] = txt
        cur["first_seen"] = dmin(cur["first_seen"], at)
        cur["last_seen"] = dmax(cur["last_seen"], at)
        if cur["closed_on"] and at > cur["closed_on"]:
            cur["closed_on"] = ""
            change(f"port {key} open again", "CHANGE", "+")
    for key in ob["closed"]:
        cur = rec["ports"].get(key)
        if cur and not cur["closed_on"] and at > cur["last_seen"]:
            cur["closed_on"] = at
            change(f"port {key} closed")

    for sid, txt in ob["hostscripts"].items():
        if newer or sid not in rec["hostscripts"]:
            rec["hostscripts"][sid] = txt


# ============================================================ render ====

DATA_RE = re.compile(r"%% netmap-data[^\n]*\n(.*?)\n%%[ \t]*(\n|$)", re.S)


# Machine data lives outside the notes, in a hidden folder of the vault. Obsidian
# ignores folders starting with a dot, so it never shows in files, search or graph.
DATA_DIR = ".netmap"  # set to <vault>/.netmap in main()


def data_path(ip):
    return os.path.join(DATA_DIR, "hosts", f"{ip}.json")


def rec_json(rec):
    rec = {k: v for k, v in rec.items() if k != "legacy"}
    return json.dumps(rec, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def service_label(p):
    s = f"{p['tunnel']}/{p['service']}" if p["tunnel"] else p["service"]
    return s + ("?" if p["method"] != "probed" and s != "unknown" else "")


def os_tag(fam):
    return {"windows-server": "os/windows/server",
            "windows-workstation": "os/windows/workstation"}.get(fam, f"os/{fam}")


def host_tags(rec, roles, finds, level, web_tags):
    tags = [f"role/{tag_part(r['role'])}" for r in roles if r["confidence"] == "confirmed"]
    tags += [f"maybe/{tag_part(r['role'])}" for r in roles if r["confidence"] == "maybe"]
    tags.append(os_tag(os_family(rec["os"])))
    tags += [f"web/{t}" for t in web_tags]
    if level:
        tags.append(f"caution/{level}")
    if finds:
        tags.append("finding")
    if rec["status"] == "down":
        tags.append("status/down")
    return tags


def render_note(rec, extra, link_ports):
    roles = classify(rec)
    finds = findings(rec, roles)
    level, why = caution_of(roles, rec)
    device, web = host_web(rec, roles)
    web_tags = list(dict.fromkeys(t["tag"] for _, st in web for t in st))
    fam = os_family(rec["os"])
    open_keys = [k for k, p in sorted_ports(rec["ports"]) if not p["closed_on"]]
    conf = [r["role"] for r in roles if r["confidence"] == "confirmed"]
    maybe = [r["role"] for r in roles if r["confidence"] == "maybe"]
    tags = host_tags(rec, roles, finds, level, web_tags)

    L = ["---", "type: network-node", f"ip: {rec['ip']}",
         f"hostname: {j(rec['hostname'])}", f"domain: {j(rec['domain'])}",
         f"os: {j(rec['os'] or 'Unknown OS')}", f"os_family: {j(fam)}",
         f"roles: {j(conf)}", f"maybe_roles: {j(maybe)}", f"caution: {j(level)}",
         f"findings: {len(finds)}", f"status: {j(rec['status'])}",
         f"first_seen: {j(short(rec['first_seen']))}", f"last_seen: {j(short(rec['last_seen']))}",
         f"open_ports: {j(open_keys)}", f"web: {j(web_tags)}", f"tags: {j(tags)}", "---", "",
         f"# {rec['ip']}", "", "## System Information", f"- **IP Address:** {rec['ip']}"]
    if rec["hostname"]:
        L.append(f"- **Hostname:** {rec['hostname']}")
    others = [n for n in rec["names"] if n.lower() != rec["hostname"].lower()]
    if others:
        L.append(f"- **Other names:** {', '.join(others)}")
    if rec["domain"]:
        L.append(f"- **Domain:** {rec['domain']}")
    if rec["os"]:
        src = f"fingerprint {rec['os_acc']}%" if rec["os_src"] == "fingerprint" else rec["os_src"]
        L.append(f"- **OS:** {rec['os']} _({src})_")
    else:
        L.append("- **OS:** Unknown")
    if rec["build"]:
        L.append(f"- **OS build:** {rec['build']} _(NTLM info)_")
    if rec["devtypes"]:
        L.append(f"- **nmap device type:** {', '.join(rec['devtypes'])}")
    if rec["mac"]:
        L.append(f"- **MAC Address:** `{rec['mac']}`" + (f" ({rec['vendor']})" if rec["vendor"] else ""))
    for v6 in rec["ipv6"]:
        L.append(f"- **IPv6:** `{v6}`")
    status = "down since " + short(rec["down_since"]) if rec["status"] == "down" else "up"
    if rec["alive_by"] and rec["status"] == "up":
        status += f" _(alive because: {rec['alive_by']})_"
    L.append(f"- **Status:** {status}")
    L.append(f"- **First seen:** {short(rec['first_seen'])} · **Last seen:** {short(rec['last_seen'])}")
    if rec["scans"]:
        L.append("- **Seen in:** " + ", ".join(f"{s['file']} ({short(s['at'])})"
                                               for s in reversed(rec["scans"][-5:])))

    if roles:
        L += ["", "## Roles", "| Role | Confidence | Evidence |", "| --- | --- | --- |"]
        for r in roles:
            L.append(f"| {r['label']} | {r['confidence']} | {'; '.join(r['evidence'])} |")
        if level:
            L += ["", f"- **Caution:** {level}: {', '.join(why)}"]

    if finds:
        L += ["", "## Scan Findings"]
        L += [f"- **{w}:** {t}" for w, t in finds]

    if web:
        L += ["", "## Web Stack"]
        for k, stack in web:
            title = _first_line(rec["ports"][k]["scripts"].get("http-title", ""))
            title = "" if "have a title" in title else title
            head = f"- **{k}:** " + (stack_text(stack) or "nothing identified")
            L.append(head + (f" · title: {_snip(title, 60)}" if title else ""))
            L += [f"    - {t['name']}: _{t['evidence']}_" for t in stack]

    L += ["", "## Graph Network Links",
          f"- **Network Segment:** [[{seg_name(*subnet_chain(rec['ip'])[-1][:2])}]]"]
    gw = pick_gateway(rec["paths"])
    if gw:
        L.append(f"- **Upstream Gateway:** [[{gw}]]")

    if rec["paths"]:
        L += ["", "## Traceroute Path"]
        for p in rec["paths"]:
            hops = " -> ".join("?" if x == "*" else f"[[{x}]]" for x in p["hops"])
            L.append(f"- ({short(p['seen'])}) {hops} -> **{rec['ip']}**")

    L += ["", "## Open Ports"]
    if rec["ports"]:
        L += ["| Port | Service | Version | First seen | Last seen | Status |",
              "| --- | --- | --- | --- | --- | --- |"]
        for k, p in sorted_ports(rec["ports"]):
            cell = f"[[Port {k.split('/')[0]}]] (`{k}`)" if link_ports else f"`{k}`"
            state = f"closed {short(p['closed_on'])}" if p["closed_on"] else "open"
            L.append(f"| {cell} | {service_label(p)} | {_prod(p) or 'N/A'} | "
                     f"{short(p['first_seen'])} | {short(p['last_seen'])} | {state} |")
    else:
        L.append("- Ports not scanned yet: nmap found the host up and was still scanning it. "
                 "Run the converter again when the scan has moved on."
                 if rec["pending"] else "- No open ports detected yet.")

    blocks = [(k, sid, txt) for k, p in sorted_ports(rec["ports"]) if not p["closed_on"]
              for sid, txt in sorted(p["scripts"].items()) if txt.strip()]
    blocks += [("host", sid, txt) for sid, txt in sorted(rec["hostscripts"].items()) if txt.strip()]
    if blocks:
        L += ["", "## Script Output"]
        for where, sid, txt in blocks:
            L += ["", f"> [!info]- {where} {sid}", "> ```"]
            L += [f"> {ln}" if ln else ">" for ln in txt.split("\n")]
            L.append("> ```")

    if rec["changes"]:
        L += ["", "## Scan Changes"]
        recent = list(reversed(rec["changes"]))
        L += [f"- {short(c['at'])}: {c['text']}" for c in recent[:15]]
        if len(recent) > 15:
            L.append(f"- ({len(recent) - 15} older changes kept in the machine data)")

    return "\n".join(L) + "\n\n" + extra


# ======================================================= read notes ====

def parse_frontmatter(text):
    m = re.match(r"---\n(.*?)\n---", text, re.S)
    fm, cur = {}, None
    if not m:
        return fm
    for line in m.group(1).splitlines():
        item = re.match(r"\s*- (.*)", line)
        if item and cur:
            try:
                fm[cur].append(json.loads(item.group(1)))
            except ValueError:
                pass
        elif ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if v == "":
                fm[k], cur = [], k
            else:
                cur = None
                try:
                    fm[k] = json.loads(v)
                except ValueError:
                    fm[k] = v.strip('"')
    return fm


def legacy_record(text, ip, path):
    """Notes written by the first two versions of this script."""
    fm = parse_frontmatter(text)
    rec = blank_record(ip)
    rec["legacy"] = True
    rec["hostname"] = clean_name(fm.get("hostname"))
    mac = str(fm.get("mac", ""))
    rec["mac"] = mac if MAC_RE.fullmatch(mac) else ""
    rec["vendor"] = clean(fm.get("vendor"), 80)
    rec["ipv6"] = [x for x in (valid_ip6(v) for v in _list(fm.get("ipv6"))) if x]
    rec["first_seen"] = valid_ts(fm.get("first_seen"))
    rec["last_seen"] = valid_ts(fm.get("last_seen"))
    # v1 notes had no dates: they stay blank, so any real scan counts as newer.
    os_name = clean(fm.get("os"), 120)
    if os_name and os_name != "Unknown OS":
        try:
            acc = max(0, min(100, int(fm.get("os_accuracy", 0))))
        except (TypeError, ValueError):
            acc = 0
        rec.update(os=os_name, os_src="fingerprint", os_acc=acc,
                   os_str=STR_FP_HIGH if acc >= 95 else STR_FP_LOW, os_seen=rec["last_seen"])
        rec["os_str"] = float(rec["os_str"])
    if isinstance(fm.get("paths"), list):
        rec["paths"] = [p for p in map(norm_path, fm["paths"]) if p]
    elif isinstance(fm.get("hops"), str) and fm["hops"]:
        p = norm_path({"hops": fm["hops"].split(","), "seen": rec["last_seen"]})
        rec["paths"] = [p] if p else []
    if isinstance(fm.get("ports"), list):
        items = fm["ports"]
    else:
        items = [{"port": m.group(1), "service": m.group(2), "version": m.group(3)}
                 for m in re.finditer(r"^\| (?:\[\[Port \d+\]\] \()?`([0-9]+/[a-z0-9]+)`\)? \| (.*?)\?? \| (.*?) \|",
                                      text, re.M)]
    for it in items:
        if not isinstance(it, dict) or not PORT_RE.fullmatch(str(it.get("port", ""))):
            continue
        p = blank_port()
        p["service"] = clean(it.get("service"), 40) or "unknown"
        ver = clean(it.get("version"), 120)
        p["product"] = "" if ver == "N/A" else ver
        p["method"] = "probed" if p["product"] else ""  # a version means -sV probed it
        p["first_seen"] = valid_ts(it.get("first_seen")) or rec["first_seen"]
        p["last_seen"] = valid_ts(it.get("last_seen")) or rec["last_seen"]
        p["closed_on"] = valid_ts(it.get("closed_on"))
        rec["ports"][it["port"]] = p
    return rec


def preserved_sections(text):
    """Everything that is not generated, verbatim (## Notes and your own sections)."""
    body = re.sub(r"\A---\r?\n.*?\r?\n---[ \t]*\r?\n?", "", text, count=1, flags=re.S)
    body = DATA_RE.sub("", body)
    parts = re.split(r"(?m)^(?=## )", body)
    pre = [ln for ln in parts[0].splitlines() if ln.strip() and not ln.startswith("# ")]
    keep = ["\n".join(pre) + "\n\n"] if pre else []
    for part in parts[1:]:
        if part.split("\n", 1)[0][3:].strip() not in GENERATED:
            keep.append(part)
    extra = "".join(keep).strip("\n")
    if not re.search(r"(?m)^## Notes[ \t]*$", extra):
        extra = (extra + "\n\n" if extra else "") + "## Notes"
    return extra + "\n"


def parse_note(path, ip):
    """Record from .netmap/hosts/<ip>.json; older notes carried it inside the note."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    rec, js = None, None
    try:
        with open(data_path(ip), "r", encoding="utf-8") as f:
            js = f.read()
        rec = normalize_record(json.loads(js), ip)
    except (OSError, ValueError, UnicodeDecodeError):
        js = None
    if rec is None:
        m = DATA_RE.search(text)  # v3.0 kept the data at the end of the note
        if m:
            try:
                rec = normalize_record(json.loads(m.group(1)), ip)
            except ValueError:
                rec = None
    if rec is None:
        rec = legacy_record(text, ip, path)
    return rec, preserved_sections(text), text, js


# ============================================================= vault ====

def scan_existing_vault(out):
    hosts, segments = {}, {}
    for root, dirs, files in os.walk(out):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for fn in sorted(files):
            if not fn.endswith(".md") or fn.startswith("."):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    head = f.read(2000)
            except (OSError, UnicodeDecodeError) as e:
                say("VAULT", fn, "!", f"cannot read: {clean(e, 100)}")
                continue
            if re.search(r"^type:\s*network-node\s*$", head, re.M):
                m = re.search(r'^ip:\s*"?([0-9.]+)"?\s*$', head, re.M)
                ip = valid_ip(m.group(1)) if m else ""
                if not ip:
                    continue
                if ip in hosts:
                    say("VAULT", ip, "!", f"duplicate note, keeping {hosts[ip]}, ignoring {path}")
                else:
                    hosts[ip] = path
            elif re.search(r"^type:\s*network-segment\s*$", head, re.M):
                segments.setdefault(fn[:-3], path)
    return hosts, segments


def get_entry(ip, hosts, cache):
    if ip in cache:
        return cache[ip]
    path = hosts.get(ip)
    if not path:
        return None
    try:
        rec, extra, text, js = parse_note(path, ip)
    except (OSError, UnicodeDecodeError) as e:
        say("VAULT", ip, "-", f"cannot read {path}: {clean(e, 100)}")
        return None
    cache[ip] = {"rec": rec, "extra": extra, "path": path, "text": text, "json": js}
    return cache[ip]


def write_entry(entry, link_ports):
    text = render_note(entry["rec"], entry["extra"], link_ports)
    js = rec_json(entry["rec"])
    changed = False
    if js != entry.get("json"):
        jp = data_path(entry["rec"]["ip"])
        os.makedirs(os.path.dirname(jp), exist_ok=True)
        write_atomic(jp, js)
        entry["json"], changed = js, True
    if text != entry["text"]:
        os.makedirs(os.path.dirname(entry["path"]), exist_ok=True)
        write_atomic(entry["path"], text)
        entry["text"], changed = text, True
    return changed


def process(meta, out, hosts, segments, cache, opts):
    name = meta["file"]
    if not os.path.isfile(meta["path"]):
        say("SCAN", name, "-", "file not found")
        return {"file": name, "start": "", "args": "", "status": "file not found"}
    if meta["args"]:
        say("SCAN", name, "*", f"nmap scan from {short(meta['start']) or 'unknown time'} {dim(meta['args'])}")
    else:
        say("SCAN", name, "*", "reading")
    up = created = updated = down = shown = hidden = with_ports = 0
    up_ips = set()

    def emit(kind, target, mark, msg):
        nonlocal shown, hidden
        if opts["verbose"] or shown < EVENT_LIMIT:
            say(kind, target, mark, msg)
            shown += 1
        else:
            hidden += 1

    for ob in iter_hosts(meta):
        ip = ob["ip"]
        entry = get_entry(ip, hosts, cache)
        events = []
        if ob["state"] == "silent":
            continue  # -Pn target that answered nothing: not a host, not "down" either
        if ob["state"] == "down":
            if entry is None:
                continue
            was = entry["rec"]["status"]
            merge(entry["rec"], ob, events)
            if write_entry(entry, opts["port_links"]) and was != entry["rec"]["status"]:
                down += 1
            for e in events:
                emit(*e)
            continue

        if ob["ip"] in up_ips:
            up -= 1
        up_ips.add(ob["ip"])
        up += 1
        with_ports += bool(ob["ports"])
        is_new = entry is None
        if is_new:
            path = os.path.join(place_host(out, ip, segments), f"{ip}.md")
            if os.path.exists(path):
                say("VAULT", ip, "!", f"{path} exists but is not a host note, skipped")
                continue
            entry = {"rec": blank_record(ip), "extra": "## Notes\n", "path": path, "text": None,
                     "json": None}
            cache[ip], hosts[ip] = entry, path
        rec = entry["rec"]
        old_roles = [] if is_new else classify(rec)
        before_roles = {r["role"] for r in old_roles if r["confidence"] == "confirmed"}
        before_finds = set() if is_new else {t for _, t in findings(rec, old_roles)}
        before_web = set() if is_new else {t["name"] for _, st in host_web(rec, old_roles)[1] for t in st}

        merge(rec, ob, events)

        roles_now = classify(rec)
        for r in roles_now:
            if r["confidence"] == "confirmed" and r["role"] not in before_roles:
                emit("ROLE", ip, "+", f"{yellow(r['label'])} {dim(r['evidence'][0])}")
        for k, st in host_web(rec, roles_now)[1]:
            new = [t for t in st if t["name"] not in before_web]
            if new:
                emit("WEB", ip, "*", f"{k} {yellow(stack_text(st))}")
        for w, t in findings(rec, roles_now):
            if t not in before_finds:
                emit("FINDING", ip, "+", f"{yellow(t)} {dim(w)}")
        for e in events:
            emit(*e)

        if write_entry(entry, opts["port_links"]):
            if is_new:
                created += 1
            else:
                updated += 1

    if not meta["kind"]:
        waiting = len(meta["hint_ips"] - meta["done_up"])
        msg = f"{up} hosts up, {green(created)} new, {updated} updated"
        if waiting:
            msg += f" ({waiting} found up, ports still being scanned)"
        if meta["silent"]:
            msg += f", {meta['silent']} gave no response {dim('(-Pn marks every target up; skipped)')}"
        if down:
            msg += f", {red(down)} now down"
        say("SCAN", name, "+", msg)
    if hidden:
        say("SCAN", name, "*", f"{hidden} more events not shown, run with -v or open summary.md")
    return report_scan(meta, up, with_ports)


# ========================================================= scan state ====
# Interrupted, empty and wrong files: say what happened and how to continue.

# nmap options whose next word is a value (so it is never mistaken for a target)
_TAKES_VALUE = {
    "-p", "-e", "-S", "-D", "-g", "-iL", "-iR", "--exclude", "--excludefile", "-oX", "-oN", "-oG",
    "-oA", "-oS", "-oM", "--script", "--script-args", "--script-args-file", "--dns-servers",
    "--proxies", "--data", "--data-string", "--data-length", "--max-retries", "--min-rate",
    "--max-rate", "--top-ports", "--port-ratio", "--version-intensity", "--ttl", "--mtu",
    "--host-timeout", "--scan-delay", "--max-scan-delay", "--min-hostgroup", "--max-hostgroup",
    "--min-parallelism", "--max-parallelism", "--min-rtt-timeout", "--max-rtt-timeout",
    "--initial-rtt-timeout", "--spoof-mac", "--stylesheet", "--datadir", "--servicedb",
    "--versiondb", "--resume", "-sI", "-b", "--exclude-ports", "--source-port", "--script-timeout",
    "--stats-every", "--release-memory", "--defeat-rst-ratelimit"}
_OUTPUT_OPTS = {"-oX", "-oN", "-oG", "-oA", "-oS", "-oM", "--resume", "--stylesheet"}
_TARGET_CAP = 1 << 20


class _TooMany(Exception):
    pass


def expand_spec(spec):
    """nmap IPv4 target spec -> list of ints, or None when it is a hostname."""
    try:
        net = ipaddress.IPv4Network(spec, strict=False)
        if net.num_addresses > _TARGET_CAP:
            raise _TooMany
        return list(range(int(net.network_address), int(net.broadcast_address) + 1))
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        pass
    octets = spec.split(".")
    if len(octets) != 4:
        return None
    lists = []
    try:
        for o in octets:
            vals = set()
            for part in o.split(","):
                part = "0-255" if part == "*" else part
                if "-" in part:
                    a, b = part.split("-", 1)
                    a, b = int(a or 0), int(b or 255)
                else:
                    a = b = int(part)
                if not 0 <= a <= b <= 255:
                    return None
                vals.update(range(a, b + 1))
            lists.append(sorted(vals))
    except ValueError:
        return None
    count = 1
    for lst in lists:
        count *= len(lst)
    if count > _TARGET_CAP:
        raise _TooMany
    return [(a << 24) | (b << 16) | (c << 8) | d
            for a in lists[0] for b in lists[1] for c in lists[2] for d in lists[3]]


def parse_targets(args_raw):
    """Split an nmap command line into targets and the rest of the options."""
    try:
        toks = shlex.split(args_raw)
    except ValueError:
        toks = args_raw.split()
    info = {"targets": [], "rest": [], "excludes": set(), "il": "", "random": False,
            "names": [], "too_big": False, "resume_from": ""}
    if toks and os.path.basename(toks[0]).lower().startswith("nmap"):
        toks = toks[1:]
    i = 0
    while i < len(toks):
        t = toks[i]
        val = toks[i + 1] if i + 1 < len(toks) else ""
        if t in _OUTPUT_OPTS:
            if t in ("-oA", "-oN", "-oG") and val:
                info["resume_from"] = val + ".gnmap" if t == "-oA" else val
            i += 2
            continue
        if t.startswith("-"):
            if t == "--randomize-hosts":
                info["random"] = True
            if t == "-iL":
                info["il"] = val
            if t == "--exclude" and val:
                for spec in val.split(","):
                    try:
                        info["excludes"].update(expand_spec(spec.strip()) or [])
                    except _TooMany:
                        pass
            if t in _TAKES_VALUE:
                info["rest"] += [t, val]
                i += 2
            else:
                info["rest"].append(t)
                i += 1
            continue
        try:
            ips = expand_spec(t)
        except _TooMany:
            info["too_big"] = True
            ips = []
        if ips is None:
            info["names"].append(t)
        else:
            info["targets"] += ips
        i += 1
    seen, ordered = set(), []
    for x in info["targets"]:
        if x not in seen and x not in info["excludes"]:
            seen.add(x)
            ordered.append(x)
    info["targets"] = ordered
    return info


def resume_advice(meta):
    name = meta["file"]
    t = parse_targets(meta["args_raw"]) if meta["args_raw"] else None
    if t and t["resume_from"]:
        say("RESUME", name, "*", f"nmap can continue it itself: {bold('nmap --resume ' + shlex.quote(t['resume_from']))}"
            f" {dim('(works with the -oN/-oG/-oA files of that run, not the XML)')}")
    if not t:
        say("RESUME", name, "*", "no nmap command line in the file; rescan the targets after "
            + (meta["last_ip"] or "the start"))
        return ""
    if t["il"]:
        say("RESUME", name, "*", f"targets came from -iL {clean(t['il'], 80)}: continue with the hosts "
            f"after {meta['last_ip'] or 'the first one'} in that list")
        return ""
    if t["names"] or t["too_big"] or not t["targets"]:
        why = "hostnames" if t["names"] else "more than a million addresses" if t["too_big"] else "no IP targets"
        say("RESUME", name, "*", f"targets include {why}, so no remaining list was written; "
            f"continue after {meta['last_ip'] or 'the start'}")
        return ""
    targets = t["targets"]
    if t["random"] or not meta["last_ip"]:
        done = {ip_key(ip) for ip in meta["seen_ips"]}
        remaining = [x for x in targets if x not in done]
        if t["random"]:
            say("RESUME", name, "!", "host order was randomized, so every target not in the file is listed")
    else:
        last = ip_key(meta["last_ip"])
        idx = targets.index(last) if last in targets else -1
        if idx < 0:
            done = {ip_key(ip) for ip in meta["seen_ips"]}
            remaining = [x for x in targets if x not in done]
        else:
            remaining = targets[idx + 1:]
    pending = {ip_key(ip) for ip in meta["hint_ips"] - meta["done_up"]}
    if pending:
        keep = set(remaining) | pending
        remaining = [x for x in targets if x in keep]
    if not remaining:
        say("RESUME", name, "*", "nothing left: every target is finished in this file")
        return ""
    base = os.path.splitext(meta["path"])[0]
    rem_path = base + ".remaining.txt"
    write_atomic(rem_path, "".join(f"{ipaddress.IPv4Address(x)}\n" for x in remaining))
    say("RESUME", name, "+", f"{len(remaining)} targets left, written to {rem_path}")
    cmd = ["nmap", *t["rest"], "-iL", rem_path, "-oX", base + ".part2.xml"]
    say("RESUME", name, "*", "continue with: " + bold(" ".join(shlex.quote(c) for c in cmd)))
    say("RESUME", name, "*", dim("nmap writes hosts in groups, so a few hosts right after the cut may "
                                 "already be done; scanning them again is harmless"))
    return rem_path


def report_scan(meta, up, with_ports):
    """Explain how the file ended. Returns the entry for scans.md."""
    name, kind = meta["file"], meta["kind"]
    entry = {"file": name, "start": meta["start"], "args": meta["args"], "status": "complete",
             "up": up, "total": meta["total"], "last": meta["last_ip"], "progress": meta["progress"],
             "remaining": "", "error": meta["error"]}
    if kind == "empty":
        say("SCAN", name, "-", "file is empty: nmap stopped before writing anything, run the scan again")
        entry["status"] = "empty file"
        return entry
    if kind == "not-xml":
        say("SCAN", name, "-", "not XML. Use nmap's XML output (-oX or -oA), not -oN/-oG text")
        entry["status"] = "not XML"
        return entry
    if kind == "not-nmap":
        say("SCAN", name, "-", f"XML, but not nmap output (root element {meta['root']})")
        entry["status"] = "not nmap XML"
        return entry
    if kind == "unsafe":
        say("SCAN", name, "-", f"refused: unsafe XML construct ({meta['error']})")
        entry["status"] = "refused"
        return entry
    if meta["truncated"] or not meta["complete"]:
        entry["status"] = "unfinished"
        where = f", last host written {meta['last_ip']}" if meta["last_ip"] else ", no host written yet"
        prog = f", nmap progress: {meta['progress']}" if meta["progress"] else ""
        say("SCAN", name, "*", f"{yellow('unfinished')} (still running or stopped): every finished host "
            f"is imported, {up} up{where}{prog}")
        say("RESUME", name, "*", dim("if it was stopped and you want the rest:"))
        entry["remaining"] = resume_advice(meta)
    elif meta["exit"] and meta["exit"] != "success":
        entry["status"] = "nmap error"
        say("SCAN", name, "!", f"nmap ended with an error: {meta['error'] or meta['exit']}")
    if entry["status"] != "complete":
        return entry
    if up == 0:
        entry["status"] = "no hosts up"
        args = meta["args_raw"]
        total = f" of {meta['total']}" if meta["total"] else ""
        if "-Pn" in args.split():
            say("SCAN", name, "!", f"0{total} hosts up even with -Pn: check the target range, "
                "routes or VPN, or the hosts are really off")
        elif meta["complete"]:
            say("SCAN", name, "!", f"0{total} hosts up. If hosts should be there, host discovery may be "
                "blocked (ICMP/ARP filtered): rerun with -Pn")
    elif with_ports == 0:
        entry["status"] = "complete, no open ports"
        if re.search(r"(^|\s)-sn(\s|$)", meta["args_raw"]):
            say("SCAN", name, "*", f"{up} hosts up, ping scan only (-sn): no ports were scanned")
        else:
            say("SCAN", name, "!", f"{up} hosts up but no open ports: filtered by a firewall, "
                "or the port range missed them")
    return entry


# =========================================================== scans.md ====

def load_scan_log(out):
    data = []
    try:
        with open(os.path.join(DATA_DIR, "scans.json"), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, UnicodeDecodeError):
        try:  # v3.1 kept it inside scans.md
            with open(os.path.join(out, "scans.md"), "r", encoding="utf-8") as f:
                m = DATA_RE.search(f.read())
            data = json.loads(m.group(1)) if m else []
        except (OSError, ValueError, UnicodeDecodeError):
            data = []
    log = []
    for e in _list(data):
        if not isinstance(e, dict):
            continue
        x = {k: clean(e.get(k), 300) for k in ("file", "args", "status", "last", "progress", "error")}
        x["status"] = "unfinished" if x["status"] == "incomplete" else x["status"]
        x["start"] = valid_ts(e.get("start"))
        x["up"] = e.get("up") if isinstance(e.get("up"), int) else ""
        x["total"] = e.get("total") if isinstance(e.get("total"), int) else None
        x["remaining"] = _safe_path(e.get("remaining"))
        log.append(x)
    return log


def _safe_path(p):
    """A file path for a note: keeps backslashes (Windows), drops what breaks markdown."""
    return re.sub(r"[|`<>\[\]]", "_", _CTRL.sub("", str(p or "")))[:300]


def write_scan_log(out, log, new):
    for e in new:
        for x in log:
            old = x.get("remaining") or ""
            if x["file"] == e["file"] and x["start"] == e["start"] and old and \
                    e["status"] != "unfinished" and old.endswith(".remaining.txt") and os.path.isfile(old):
                try:  # our own leftover from when this scan was still unfinished
                    os.remove(old)
                except OSError:
                    pass
        log = [x for x in log if not (x["file"] == e["file"] and x["start"] == e["start"])] + [e]
    log.sort(key=lambda e: e.get("start") or "")
    L = ["---", "type: netmap-index", "---", "", "# Imported Scans", "",
         "Every nmap file given to converter.py. Status says whether nmap finished.", "",
         "| Started | File | Status | Hosts up | Last host | Command |", "| --- | --- | --- | --- | --- | --- |"]
    for e in reversed(log):
        up = f"{e.get('up', '')}" + (f" of {e['total']}" if e.get("total") else "")
        L.append(f"| {short(e.get('start', ''))} | {_cell(e['file'], 50)} | {_cell(e['status'], 40)} | "
                 f"{up} | {e.get('last') or ' '} | {_cell(e.get('args', ''), 120)} |")
    bad = [e for e in log if e["status"] == "unfinished" and e.get("remaining")]
    if bad:
        L += ["", "## Unfinished", ""]
        L += [f"- {e['file']}: remaining targets in `{_safe_path(e['remaining'])}`" for e in bad]
    os.makedirs(DATA_DIR, exist_ok=True)
    write_atomic(os.path.join(DATA_DIR, "scans.json"), json.dumps(log, ensure_ascii=False, indent=1) + "\n")
    write_atomic(os.path.join(out, "scans.md"), "\n".join(L) + "\n")
    return log


# =========================================================== indexes ====

def _first_line(txt):
    return next((ln.strip() for ln in txt.split("\n") if ln.strip()), "")


def _code(ips):
    return ["```text", *ips, "```"] if ips else []


def _cell(s, n=80):
    return _snip(s, n) or " "


_TOP = {"windows-server": "Windows", "windows-workstation": "Windows", "windows": "Windows",
        "linux": "Linux", "android": "Android", "bsd": "BSD", "macos": "macOS", "ibm": "IBM i / z/OS",
        "unix": "Unix (AIX, Solaris, HP-UX)", "network-os": "Network device OS",
        "esxi": "VMware ESXi", "other": "Other / embedded", "mixed": "Unclear (guess mixes families)",
        "unknown": "Unknown (no OS data)"}


def windows_version(name):
    """'Microsoft Windows 10 1709 - 22H2' -> 'Windows 10'. Ambiguous guesses say so."""
    vers = []
    for part in re.split(r"\s+or\s+|,\s+", name):
        m = re.search(r"Windows (?:Server )?(?:\(R\) )?(20\d\d)( R2)?", part, re.I)
        if m:
            vers.append(f"Windows Server {m.group(1)}{m.group(2) or ''}")
            continue
        m = re.search(r"Windows (XP|Vista|7|8\.1|8|10|11|NT|2000)\b(?:\s*-\s*(11|10))?", part, re.I)
        if m:
            vers.append(f"Windows {m.group(1)}" + (f" or {m.group(2)}" if m.group(2) else ""))
    vers = list(dict.fromkeys(vers))
    if len(vers) == 1:
        return vers[0]
    if vers:
        return " or ".join(vers)
    return "Windows, version not given"


def tag_overview(info):
    """Every tag present in the vault, with host counts, ready for graph groups."""
    counts = {}
    for r, roles, finds in info:
        level, _ = caution_of(roles, r)
        _, web = host_web(r, roles)
        web_tags = list(dict.fromkeys(t["tag"] for _, st in web for t in st))
        for t in host_tags(r, roles, finds, level, web_tags):
            counts[t] = counts.get(t, 0) + 1
            if t.startswith("os/windows/"):
                counts["os/windows"] = counts.get("os/windows", 0) + 1  # parent of nested tags
    order = ["role/", "maybe/", "caution/", "os/", "web/", "finding", "status/"]
    rows = sorted(counts.items(), key=lambda x: (next(i for i, o in enumerate(order) if x[0].startswith(o)),
                                                 x[0]))
    L = ["## Tags In This Vault", "",
         "Paste the query into Graph view > Groups (or search). The first matching group wins, so "
         "put the most specific ones on top. `tag:#os/windows` also matches its nested tags.", "",
         "| Query | Hosts |", "| --- | --- |"]
    L += [f"| `tag:#{t}` | {n} |" for t, n in rows]
    return L + [""]


def os_overview(recs):
    """How many of each OS, with how sure each count is."""
    groups = {}
    for r in recs:
        fam = os_family(r["os"])
        top = _TOP.get(fam, "Other / embedded")
        g = groups.setdefault(top, {"n": 0, "self": 0, "strong": 0, "weak": 0, "detail": {},
                                    "server": 0, "client": 0, "win_ports": 0})
        g["n"] += 1
        s = r["os_str"]
        g["self" if s >= STR_SELF else "strong" if s >= STR_FP_HIGH else "weak"] += 1 if r["os"] else 0
        if top == "Windows":
            v = windows_version(r["os"])
            g["detail"][v] = g["detail"].get(v, 0) + 1
            g["server"] += fam == "windows-server"
            g["client"] += fam == "windows-workstation"
        elif top == "Unknown (no OS data)":
            open_k = {k for k, p in r["ports"].items() if not p["closed_on"]}
            g["win_ports"] += {"135/tcp", "445/tcp"} <= open_k
    rows = sorted(groups.items(), key=lambda x: (x[0].startswith("Unknown"), -x[1]["n"]))
    L = ["## Operating Systems", "",
         "One row per OS. *From the host*: the host said it (SMB, vmware, SNMP). *Fingerprint "
         "95%+*: nmap's OS guess with high accuracy. *Weak guess*: below 95%, or only -sV saying "
         "\"Windows\" or \"Linux\".", "",
         "| OS | Hosts | From the host | Fingerprint 95%+ | Weak guess | Breakdown |",
         "| --- | --- | --- | --- | --- | --- |"]
    for top, g in rows:
        parts = []
        if top == "Windows":
            parts.append(f"servers {g['server']}, workstations {g['client']}, "
                         f"unclear {g['n'] - g['server'] - g['client']}")
            parts += [f"{v}: {n}" for v, n in sorted(g["detail"].items(), key=lambda x: -x[1])]
        elif top == "Linux":
            parts.append("kernel ranges are fingerprint guesses, see hosts.md per host")
        elif top.startswith("Unknown") and g["win_ports"]:
            parts.append(f"{g['win_ports']} have 135 + 445 open (Windows ports, not counted as Windows)")
        L.append(f"| **{top}** | {g['n']} | {g['self']} | {g['strong']} | {g['weak']} | "
                 f"{_cell(' · '.join(parts), 400)} |")
    return L + [""]


def update_gateways(recs, hosts, cache, link_ports):
    """Every traceroute hop is a router. Notes whose router status changed are rewritten."""
    behind = {}
    for r in recs:
        for p in r["paths"]:
            for hop in p["hops"]:
                if hop != "*" and hop != r["ip"]:
                    behind.setdefault(hop, set()).add(r["ip"])
    new = {ip: len(s) for ip, s in behind.items()}
    old = dict(GATEWAYS)
    GATEWAYS.clear()
    GATEWAYS.update(new)
    fresh = sorted((ip for ip in new if ip not in old), key=ip_key)
    for ip in fresh[:EVENT_LIMIT]:
        say("ROUTER", ip, "!", f"{yellow('router')} on the traceroute path to {new[ip]} hosts, caution high"
            + ("" if ip in hosts else dim(" (not scanned itself)")))
    if len(fresh) > EVENT_LIMIT:
        say("ROUTER", "", "*", f"{len(fresh) - EVENT_LIMIT} more routers, see Handle With Care in summary.md")
    for ip in set(old) | set(new):
        if old.get(ip) != new.get(ip) and ip in hosts:
            e = get_entry(ip, hosts, cache)
            if e:
                write_entry(e, link_ports)
    os.makedirs(DATA_DIR, exist_ok=True)
    write_atomic(os.path.join(DATA_DIR, "gateways.json"), json.dumps(new, indent=1, sort_keys=True) + "\n")


def write_indexes(out, hosts, cache, scan_log=(), link_ports=True):
    recs = []
    for ip in hosts:
        e = get_entry(ip, hosts, cache)
        if e:
            if "%% netmap-data" in (e["text"] or ""):
                write_entry(e, link_ports)  # move old in-note data out to .netmap
            recs.append(e["rec"])
    update_gateways(recs, hosts, cache, link_ports)
    recs.sort(key=lambda r: ip_key(r["ip"]))
    info = []
    for r in recs:
        ro = classify(r)
        info.append((r, ro, findings(r, ro)))

    write_atomic(os.path.join(out, "hosts.txt"), "".join(f"{r['ip']}\n" for r in recs))

    H = ["---", "type: netmap-index", "---", "", "# All Hosts", "",
         "Every host ever seen by converter.py. Plain text on purpose: no links, so this file "
         "adds no hub to the graph. The same IPs for tools: `hosts.txt`.", "",
         "| IP | Hostname | OS | Roles | Open ports | Status | Last seen |",
         "| --- | --- | --- | --- | --- | --- | --- |"]
    for r, roles, _ in info:
        open_keys = [k.split("/")[0] for k, p in sorted_ports(r["ports"]) if not p["closed_on"]]
        ports = ", ".join(open_keys[:8]) + (f" +{len(open_keys) - 8}" if len(open_keys) > 8 else "")
        H.append(f"| {r['ip']} | {_cell(r['hostname'], 50)} | {_cell(r['os'] or 'Unknown', 50)} | "
                 f"{_cell(role_list(roles), 60)} | {ports or ' '} | {r['status']} | {short(r['last_seen'])} |")
    write_atomic(os.path.join(out, "hosts.md"), "\n".join(H) + "\n")

    n_up = sum(1 for r in recs if r["status"] == "up")
    last = max((r["last_seen"] for r in recs), default="")
    S = ["---", "type: netmap-index", "---", "", "# Network Summary", "",
         "| Hosts | Up | Down | With roles | With findings | Latest scan |",
         "| --- | --- | --- | --- | --- | --- |",
         f"| {len(recs)} | {n_up} | {len(recs) - n_up} | {sum(1 for _, ro, _ in info if ro)} | "
         f"{sum(1 for _, _, f in info if f)} | {short(last)} |", "",
         "Plain text on purpose (no graph links). A role with **?** is a *maybe*: only a port "
         "number, a hostname or a certificate name points to it. Confirmed roles come from what "
         "the service said about itself or from a strong port combination.", ""]

    unfinished = [e for e in scan_log if e.get("status") == "unfinished"]
    problems = [e for e in scan_log if e.get("status") not in ("complete", "complete, no open ports",
                                                               "unfinished")]
    if unfinished:
        S += ["## Unfinished Scans", "",
              "Still running or stopped. Every host nmap finished is already in the notes; "
              "run the converter again on the same file to pick up new hosts.", "",
              "| File | Hosts up so far | Last host | Remaining targets (if stopped) |",
              "| --- | --- | --- | --- |"]
        S += [f"| {_cell(e['file'], 50)} | {e.get('up', '')} | {e.get('last') or ' '} | "
              f"{_safe_path(e.get('remaining')) or ' '} |" for e in unfinished]
        S.append("")
    if problems:
        S += ["## Scan Problems", "", "| File | Status |", "| --- | --- |"]
        S += [f"| {_cell(e['file'], 50)} | {e['status']} |" for e in problems]
        S.append("")
    if unfinished or problems:
        S += ["Every imported scan: scans.md", ""]

    S += os_overview(recs)
    S += tag_overview(info)

    for group in GROUPS:
        rows, sure, unsure = [], [], []
        for r, roles, _ in info:
            for ro in roles:
                if ro["group"] != group:
                    continue
                rows.append(f"| {r['ip']} | {_cell(r['hostname'], 40)} | {ro['label']}"
                            f"{'?' if ro['confidence'] == 'maybe' else ''} | {_cell(ro['evidence'][0], 90)} |")
                (sure if ro["confidence"] == "confirmed" else unsure).append(r["ip"])
        if not rows:
            continue
        S += [f"## {group}", "", "| IP | Hostname | Role | Evidence |", "| --- | --- | --- | --- |", *rows, ""]
        sure = list(dict.fromkeys(sure))
        unsure = [ip for ip in dict.fromkeys(unsure) if ip not in sure]
        if sure:
            S += ["Confirmed:", *_code(sure), ""]
        if unsure:
            S += ["Maybe:", *_code(unsure), ""]

    care = [(r, *caution_of(ro, r)) for r, ro, _ in info]
    care = [c for c in care if c[1]]
    known = {r["ip"] for r in recs}
    for ip, n in GATEWAYS.items():  # routers that only appear as traceroute hops
        if ip not in known:
            care.append(({"ip": ip, "hostname": ""}, "high",
                         [f"Router seen only as a traceroute hop ({n} hosts behind it), not scanned itself"]))
    if care:
        care.sort(key=lambda c: (-CAUTION_RANK[c[1]], ip_key(c[0]["ip"])))
        S += ["## Handle With Care", "",
              "Known fragile or business critical device classes, including routers and switches "
              "(old IOS and cheap switches can crash or drop traffic under heavy scans). Exclude them "
              "from aggressive scans (Nessus, -T4, brute force) or use a gentle policy.", "",
              "| IP | Hostname | Caution | Why |", "| --- | --- | --- | --- |"]
        S += [f"| {r['ip']} | {_cell(r['hostname'], 40)} | {lvl} | {_cell(', '.join(why), 90)} |"
              for r, lvl, why in care]
        S += ["", "Exclude list:", *_code([r["ip"] for r, _, _ in care]), ""]

    frows = sorted(((t, r, w) for r, _, fs in info for w, t in fs),
                   key=lambda x: (x[0], ip_key(x[1]["ip"])))
    if frows:
        S += ["## Scan Findings", "", "| Finding | IP | Hostname | Where |", "| --- | --- | --- | --- |"]
        S += [f"| {_cell(t, 100)} | {r['ip']} | {_cell(r['hostname'], 40)} | {w} |" for t, r, w in frows]
        S.append("")

    web, stacks, bare = [], {}, []
    for r, roles, _ in info:
        device, ports = host_web(r, roles)
        if device:
            ports = [(k, None) for k, p in sorted_ports(View(r).open) if is_web(p)]
        for k, stack in ports:
            t = _first_line(r["ports"][k]["scripts"].get("http-title", ""))
            if not t or "have a title" in t:
                t = "(no title)"
            what = f"device: {device}" if device else stack_text(stack)
            if t == "(no title)" and not what:
                bare.append(f"{r['ip']}:{k.split('/')[0]}")
                continue
            web.append(f"| {r['ip']} | {k} | {_cell(t, 60)} | {_cell(what, 90)} |")
            for tech in stack or []:
                stacks.setdefault(tech["name"], []).append(f"{r['ip']}:{k.split('/')[0]}")
    if web:
        S += ["## Web Services", "", "Stack comes from headers, cookies, generator and auth that nmap "
              "saw. Devices show what they are instead of their web UI.", "",
              "| IP | Port | Title | Stack |", "| --- | --- | --- | --- |", *web, ""]
    if bare:
        if not web:
            S += ["## Web Services", ""]
        S += [f"{len(bare)} more web ports with no title and nothing identified "
              "(scan them with -sV and default scripts to learn more):", *_code(bare), ""]
    if stacks:
        S += ["## Web Technologies", "", "| Technology | Hosts | Where |", "| --- | --- | --- |"]
        for name, where in sorted(stacks.items(), key=lambda x: (-len(x[1]), x[0])):
            shown = ", ".join(where[:12]) + (f" +{len(where) - 12}" if len(where) > 12 else "")
            S.append(f"| {name} | {len(where)} | {shown} |")
        S.append("")

    changes = sorted(((c["at"], r["ip"], c["text"]) for r in recs for c in r["changes"]), reverse=True)[:50]
    if changes:
        S += ["## Recent Changes", "", "| When | IP | Change |", "| --- | --- | --- |"]
        S += [f"| {short(a)} | {ip} | {_cell(t, 120)} |" for a, ip, t in changes]
        S.append("")

    write_atomic(os.path.join(out, "summary.md"), "\n".join(S).rstrip() + "\n")
    return len(recs)


# ============================================================== help ====

def print_help():
    def head(s):
        print(yellow(s))

    def opt(flag, text):
        print(f"  {green(f'{flag:<22}')} {text}")

    print(f"{bold('converter.py')} {dim('v' + VERSION)}  Nmap XML to Obsidian notes and graph, incremental")
    print()
    head("USAGE")
    print("  python converter.py <scan.xml> [more.xml ...] [options]")
    print()
    head("OPTIONS")
    opt("-o, --output DIR", f"vault folder for the notes (default: {DEFAULT_OUT})")
    opt("-P, --no-port-links", "write ports as plain text, no [[Port N]] hub nodes in the graph")
    opt("-v, --verbose", f"print every role, finding and change (default: first {EVENT_LIMIT} per scan)")
    opt("-n, --no-color", "plain output (automatic when piped or NO_COLOR is set)")
    opt("--prune-ghosts", "delete notes with nothing in them: no open port ever, no MAC, no OS,")
    print(f"  {'':<22} no script output. Notes you wrote in are never deleted. Hosts that only")
    print(f"  {'':<22} answered a ping or a reset are deleted too. Add a range to limit it:")
    print(f"  {'':<22} --prune-ghosts 10.10.10.0/24 (or 10.10.10.1-50, or several with commas).")
    print(f"  {'':<22} No scan file needed.")
    opt("-h, --help", "show this help")
    print()
    head("EXAMPLES")
    print(f"  {dim('# many scans at once, any order: they are sorted by the scan time inside each XML')}")
    print("  python converter.py 10.10.10.0.xml 192.168.13.0.xml")
    print(f"  {dim('# one vault folder per engagement')}")
    print("  python converter.py scans/*.xml -o ClientA/Nmap_Nodes")
    print()
    head("BEST SCAN FOR THIS TOOL")
    print('  nmap -sV --script "default,http-headers" -O --traceroute -v -oA scan <targets>')
    print(f"  {green('-sV --script')} the evidence for roles and web stack (banners, titles, headers,")
    print("               cookies, certificates, SMB/LDAP info). default is what -sC runs.")
    print(f"  {green('-O')}           OS fingerprint (a guess, shown with its accuracy)")
    print(f"  {green('-v')}           makes nmap record down hosts, so hosts that disappear get marked")
    print(f"  {green('--traceroute')} gateway and path links in the graph")
    print(f"  {green('-oA scan')}     writes scan.xml for this tool, plus scan.gnmap so an interrupted")
    print("               scan can continue with nmap --resume scan.gnmap")
    print("  A bare -sS scan works too, but most hosts then only get ports and an OS guess.")
    print()
    head("OUTPUT")
    print(f"  {DEFAULT_OUT}/")
    print("    summary.md    OS counts, high value roles, handle with care, findings, web stack, changes")
    print("    hosts.md      every host ever seen (plain table, no graph links)")
    print("    hosts.txt     the same IPs, one per line, for nmap -iL, nxc, Nessus")
    print("    scans.md      every imported file and whether nmap finished it")
    print("    10.0.0.0/10.10.0.0/10.10.10.0/10.10.10.5.md   one note per host, by IP")
    print()
    head("INTERRUPTED, EMPTY OR WRONG FILES")
    print("  Unfinished scans (still running, or stopped) are imported as far as they got: every host")
    print("  nmap finished becomes a note. Run the converter again on the same file to add new hosts.")
    print("  The last host written is shown, and the targets left go to <scan>.remaining.txt next to")
    print("  the XML with the command to continue, in case it was stopped.")
    print("  Empty files, -oN/-oG text, non nmap XML and scans with 0 hosts up are reported, not skipped silently.")
    print()
    head("OUTPUT LOOKS LIKE")
    say("SCAN", "10.10.10.0.xml", "*", f"nmap scan from 2026-11-12 10:03 {dim('nmap -sV -sC -O 10.10.10.0/24')}")
    say("ROLE", "10.10.10.5", "+", f"{yellow('Domain Controller')} {dim('88/tcp + 389/tcp + 445/tcp open')}")
    say("FINDING", "10.10.10.20", "+", f"{yellow('SMB signing not required')} {dim('445/tcp')}")
    say("CHANGE", "10.10.10.31", "!", "OS Windows 7 Professional 7601 -> Windows 11 Pro 22631 (smb-os-discovery)")
    say("DOWN", "10.10.10.40", "-", "host did not respond (down in scan)")
    say("SCAN", "10.10.10.0.xml", "+", f"240 hosts up, {green(12)} new, 31 updated, {red(1)} now down")
    print()
    head("GRAPH COLORS")
    print("  Graph view > Groups. The first matching group wins, so put specific roles on top:")
    for q in ("tag:#role/dc", "tag:#role/esxi OR tag:#role/vcenter", "tag:#caution/critical",
              "tag:#caution/high", "tag:#os/windows/server", "tag:#os/windows", "tag:#os/linux",
              "tag:#status/down"):
        print(f"  {green(q)}")
    print("  tag:#os/windows also matches os/windows/server and os/windows/workstation (nested tags).")
    print("  These are examples. summary.md lists the tags really in your vault, with host counts.")
    print()
    head("ALL TAGS")
    for g in GROUPS:
        roles = " ".join(f"role/{r['role']}" for r in RULES if r["group"] == g)
        print(f"  {dim(g + ':')} {green(roles)}")
    print(f"  {dim('Maybe roles:')} {green('maybe/<role>')} (same names, when the evidence is weak)")
    oses = " ".join(dict.fromkeys(os_tag(f) for f in _TOP))
    print(f"  {dim('OS:')} {green(oses)}")
    print(f"  {dim('Web:')} {green(' '.join('web/' + t['tag'] for t in WEB_TECH))}")
    print(f"  {dim('Other:')} {green('caution/high caution/critical finding status/down')}")
    print()
    head("WEB STACK")
    print("  Server, language, framework and CMS from headers, cookies, generator, robots.txt and auth")
    print("  (Laravel from laravel_session, ASP.NET from its headers, WordPress from generator...).")
    print("  Each item shows what proved it. Nmap does not run JavaScript, so React or Vue front ends")
    print("  are mostly invisible. Devices (cameras, printers, iLO...) show what they are instead.")
    print()
    head("OLD SYSTEMS")
    print(f"  End of support Windows (NT to 10, Server 2003 to 2012) and outdated software (as of {EOL_AS_OF}).")
    print("  XP, 2000 and 2003 also get caution high (fragile, often ATMs, medical or OT boxes) and")
    print("  hints for MS08-067, MS17-010 and BlueKeep. From a fingerprint they say 'Likely'.")
    print()
    head("ROUTERS AND SWITCHES")
    print("  Any IP that shows up as a hop in other hosts' traceroute is a router: caution high, even when")
    print("  it was never scanned itself. Weak Cisco/Juniper/... fingerprints, network vendor MACs and")
    print("  Cisco Smart Install (4786) give a maybe. All of them go to the exclude list in summary.md.")
    print()
    head("HOW DATA IS MERGED")
    print("  Notes are matched by their ip: field, so you can move them around.")
    print("  The newest scan wins when it has the data. Empty data never overwrites anything.")
    print("  OS keeps its source: what the host says (smb-os-discovery) beats a fingerprint guess.")
    print("  A weaker newer guess never replaces a stronger older fact; it is logged as a change instead.")
    print("  Nothing is deleted. Closed ports stay with a closed date, missing hosts keep their last seen.")
    print("  A host is marked down only when a newer scan lists it as down (needs nmap -v).")
    print()
    head("ACCURACY")
    print("  confirmed  the service said it (banner, title, version, script output) or a strong")
    print("             port combination (DC: 88 + 389 + 445)")
    print("  maybe ?    only a port number, a hostname or a certificate name points to it")
    print("  A service name ending in ? came from the port number only (no -sV), as in nmap.")
    print("  Every role and finding shows its evidence in the note. Nothing is guessed in prose.")
    print()
    head("SAFE TO EDIT")
    print("  Your text under ## Notes and any ## section you add yourself are kept on every run.")
    print("  Rebuilt each run: " + ", ".join(sorted(GENERATED)) + ".")
    print(f"  History (ports over time, script output, changes) is kept in {DEFAULT_OUT}/.netmap/,")
    print("  one JSON file per host. Obsidian ignores dot folders, so it never shows in files,")
    print("  search or graph. Delete it and the next run rebuilds from the notes, minus that history.")
    print()
    head("EXTENDING")
    print("  Roles live in RULES near the top of the file, findings in script_findings().")
    print("  Add a rule with a regex and it applies to every note on the next run.")


# ============================================================== main ====

def parse_args(argv):
    opts = {"output": DEFAULT_OUT, "port_links": True, "verbose": False, "color": True, "prune": False,
            "scope": None, "scope_text": "", "help": False, "files": []}
    args = []
    for a in argv:
        if a.startswith("-") and not a.startswith("--") and len(a) > 2:
            args += [f"-{ch}" for ch in a[1:]]
        else:
            args.append(a)
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-h", "--help"):
            opts["help"] = True
        elif a in ("-o", "--output"):
            if i + 1 >= len(args):
                return opts, f"{a} needs a folder name"
            i += 1
            opts["output"] = args[i]
        elif a.startswith("--output="):
            opts["output"] = a.split("=", 1)[1]
        elif a in ("-P", "--no-port-links"):
            opts["port_links"] = False
        elif a in ("-v", "--verbose"):
            opts["verbose"] = True
        elif a == "--prune-ghosts" or a.startswith("--prune-ghosts="):
            opts["prune"] = True
            value = a.split("=", 1)[1] if "=" in a else ""
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if not value and RANGE_LIKE.fullmatch(nxt):  # optional range right after the flag
                value, i = nxt, i + 1
            if value:
                scope = parse_scope(value)
                if scope is None:
                    return opts, f"not a valid range for --prune-ghosts: {value}"
                opts["scope"], opts["scope_text"] = scope, value
        elif a in ("-n", "--no-color"):
            opts["color"] = False
        elif a.startswith("-"):
            return opts, f"unknown option {a}"
        else:
            opts["files"].append(a)
        i += 1
    return opts, None


RANGE_LIKE = re.compile(r"[0-9][0-9.,/*-]*")


def parse_scope(text):
    """'10.10.10.0/24', '10.10.10.1-50', '10.0.0.0/8,192.168.1.0/24' -> list of matchers."""
    parts = []
    try:
        single = expand_spec(text)  # nmap style, commas inside octets (10.0.0.1,3,5)
    except _TooMany:
        single = None
    if single is not None and "/" not in text:
        return [set(single)]
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            parts.append(ipaddress.IPv4Network(chunk, strict=False))
            continue
        except ValueError:
            pass
        try:
            ips = expand_spec(chunk)
        except _TooMany:
            return None
        if ips is None:
            return None
        parts.append(set(ips))
    return parts or None


def in_scope(ip, scope):
    if scope is None:
        return True
    addr, key = ipaddress.IPv4Address(ip), ip_key(ip)
    return any(key in m if isinstance(m, set) else addr in m for m in scope)


def is_ghost(entry):
    """Nothing worth keeping: no open port ever, no MAC, no OS, no scripts, nothing you wrote.
    How it once answered does not matter: a reset from a firewall or a lone ping reply
    leaves a note with nothing in it."""
    r = entry["rec"]
    return (not r["ports"] and not r["mac"] and not r["os"]
            and not r["hostscripts"] and not r["pending"]
            and entry["extra"].strip() == "## Notes")


def handle_ghosts(out, hosts, cache, prune, scope=None, scope_text=""):
    ghosts = []
    for ip in list(hosts):
        e = get_entry(ip, hosts, cache)
        if e and is_ghost(e):
            ghosts.append(ip)
    if not ghosts:
        if prune:
            say("VAULT", out, "*", "no empty notes" + (f" in {scope_text}" if scope_text else "") + ", nothing deleted")
        return
    ghosts.sort(key=ip_key)
    if prune and scope is not None:
        outside = [ip for ip in ghosts if not in_scope(ip, scope)]
        ghosts = [ip for ip in ghosts if in_scope(ip, scope)]
        if outside:
            say("VAULT", out, "*", f"{len(outside)} empty notes outside {scope_text} left alone")
        if not ghosts:
            say("VAULT", out, "*", f"no empty notes in {scope_text}, nothing deleted")
            return
    if not prune:
        say("VAULT", out, "!", f"{len(ghosts)} notes have nothing in them (no open port ever, no MAC, "
            "no OS, no script output): run with --prune-ghosts to delete them")
        return
    for ip in ghosts:
        for path in (hosts[ip], data_path(ip)):
            try:
                os.remove(path)
            except OSError:
                pass
        hosts.pop(ip, None)
        cache.pop(ip, None)
    shown = ", ".join(ghosts[:10]) + (f" +{len(ghosts) - 10} more" if len(ghosts) > 10 else "")
    where = f" in {scope_text}" if scope_text else ""
    say("VAULT", out, "+", f"deleted {len(ghosts)} empty notes{where}: {shown}")


def prune_orphans(hosts):
    """History of a note you deleted goes too, so deleting a note fully forgets the host."""
    folder = os.path.join(DATA_DIR, "hosts")
    try:
        names = os.listdir(folder)
    except OSError:
        return
    for fn in names:
        ip = valid_ip(fn[:-5]) if fn.endswith(".json") else ""
        if ip and ip not in hosts:
            try:
                os.remove(os.path.join(folder, fn))
            except OSError:
                pass


def main(argv):
    for stream in (sys.stdout, sys.stderr):
        try:  # a banner with odd characters must never crash the console (Windows cp1252)
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    opts, err = parse_args(argv)
    if os.name == "nt":
        os.system("")  # turn on ANSI colors in the Windows console
    Color.on = opts["color"] and sys.stdout.isatty() and "NO_COLOR" not in os.environ

    if opts["help"] or (not argv):
        print_help()
        return 0
    if err:
        say("ERROR", "", "-", f"{err} (see python converter.py -h)")
        return 2
    if not opts["files"] and not opts["prune"]:
        say("ERROR", "", "-", "no scan files given (see python converter.py -h)")
        return 2

    global DATA_DIR
    out = opts["output"]
    os.makedirs(out, exist_ok=True)
    DATA_DIR = os.path.join(out, ".netmap")
    try:
        with open(os.path.join(DATA_DIR, "gateways.json"), "r", encoding="utf-8") as f:
            GATEWAYS.update({ip: int(n) for ip, n in json.load(f).items() if valid_ip(ip)})
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    if not SAFE_XML:
        say("VAULT", out, "!", "defusedxml not installed, using the stdlib parser "
            "(fine for your own scans, pip install defusedxml for files from others)")
    hosts, segments = scan_existing_vault(out)
    for ip, path in hosts.items():
        PLACES.setdefault(ip.rsplit(".", 1)[0], os.path.dirname(path))
    LEGACY_LAYOUT[0] = any(re.fullmatch(r"(?!10\.)\d+\.0\.0\.0_8", n) for n in segments)
    say("VAULT", out, "*", f"{len(hosts)} host notes indexed")

    cache, entries = {}, []
    metas = sorted((scan_meta(f) for f in opts["files"]), key=lambda m: m["start"])
    for meta in metas:
        entries.append(process(meta, out, hosts, segments, cache, opts))

    handle_ghosts(out, hosts, cache, opts["prune"], opts["scope"], opts["scope_text"])
    prune_orphans(hosts)
    log = write_scan_log(out, load_scan_log(out), [e for e in entries if e.get("start")])
    total = write_indexes(out, hosts, cache, log, opts["port_links"])
    say("VAULT", out, "+", f"{total} hosts in the vault, hosts.md, hosts.txt, summary.md and scans.md written")
    bad = [e for e in entries if e["status"] not in ("complete", "complete, no open ports", "unfinished")]
    running = [e for e in entries if e["status"] == "unfinished"]
    if running:
        say("VAULT", out, "*", f"{len(running)} unfinished scan(s) imported as far as they got: "
            + ", ".join(e["file"] for e in running[:5]))
    if bad:
        say("VAULT", out, "!", f"{len(bad)} of {len(entries)} files had problems: "
            + ", ".join(f"{e['file']} ({e['status']})" for e in bad[:5]))
    say("VAULT", out, "*", f"open '{out}' as (or inside) your Obsidian vault")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print()
        say("ERROR", "", "-", "interrupted, notes already written are complete (atomic writes)")
        sys.exit(130)
