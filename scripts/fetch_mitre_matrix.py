"""Fetch the MITRE ATT&CK Enterprise matrix (techniques only, no sub-techniques)
and trim it to a tiny JSON file TinySIEM ships with.

MITRE publishes the full STIX bundle at:
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

We pull it once with stdlib only (urllib + json), filter to top-level
``attack-pattern`` objects that are NOT sub-techniques, and bucket each
technique under every ``mitre-attack`` kill-chain phase it belongs to. A
single technique may legitimately belong to multiple tactics (e.g. T1078
"Valid Accounts" is listed under Initial Access, Persistence, Privilege
Escalation, and Defense Evasion); we honor that.

The output is committed to ``app/rules/data/mitre_enterprise.json`` so the
TinySIEM Detection Coverage view works offline, with no STIX dependency.

Usage:
    python scripts/fetch_mitre_matrix.py                    # default output path
    python scripts/fetch_mitre_matrix.py --out path/to.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# MITRE publishes ATT&CK releases as git tags in `mitre/cti` (e.g. ATT&CK-v17.1).
# The default URL points at the latest release tag — fetched from the GitHub
# API — so a fresh checkout always pulls a stable, reviewed bundle rather than
# whatever happens to be on master (which moves continuously).
_BUNDLE_TEMPLATE = (
    "https://raw.githubusercontent.com/mitre/cti/{tag}/"
    "enterprise-attack/enterprise-attack.json"
)
_GH_TAGS_API = "https://api.github.com/repos/mitre/cti/tags?per_page=100"
_UA = "TinySIEM-mitre-fetcher/1.0 (self-hosted SIEM; https://github.com/netsecid/tinysiem)"
_DEFAULT_OUT = Path(__file__).resolve().parent.parent / "app" / "rules" / "data" / "mitre_enterprise.json"

# Canonical ATT&CK Enterprise tactic ORDER (ATT&CK v12+). Any tactic in the
# bundle that is not in this list is dropped with a warning log line.
_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def _fetch_bundle(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    print(f"Downloading {url} ...", file=sys.stderr)
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:  # nosec B310  # nosemgrep: dynamic-urllib-use-detected
            raw = resp.read()
    except urllib.error.URLError as exc:
        raise SystemExit(f"ERROR: failed to fetch MITRE bundle: {exc}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: MITRE bundle is not valid JSON: {exc}")


def _extract_techniques(bundle: dict) -> tuple[list[dict], str]:
    """Return ([{tactic: [...techniques...]}], version_string).

    Sub-techniques are deliberately excluded from the matrix (TinySIEM only
    validates top-level IDs; sub-techniques are resolved via the prefix
    technique when needed).
    """
    objects = bundle.get("objects") or []
    # x_mitre_version lives on each object (and the bundle root on newer revs);
    # pick the max so the resulting label reflects the most recent release in
    # the bundle (the published STIX rev).
    versions = [bundle.get("x_mitre_version")] + [
        o.get("x_mitre_version") for o in objects if o.get("x_mitre_version")
    ]
    version = max((v for v in versions if v), default="unknown")

    # Map attack-pattern-id -> {name, kill_chain_phases}
    by_id: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_is_subtechnique") is True:
            continue
        if obj.get("revoked") is True:
            continue
        if obj.get("x_mitre_deprecated") is True:
            continue
        ext_refs = obj.get("external_references") or []
        attack_id = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                attack_id = ref["external_id"]
                break
        if not attack_id:
            continue
        by_id[attack_id] = {
            "id": attack_id,
            "name": obj.get("name") or attack_id,
            "kill_chain_phases": obj.get("kill_chain_phases") or [],
        }

    # Build tactic -> sorted techniques
    # MITRE STIX uses lowercase kebab-case `phase_name` (e.g. "initial-access");
    # the public ATT&CK docs and the TinySIEM `_TACTICS` list use Title Case
    # with the conjunction ("and", "or") lowercase (e.g. "Command and Control",
    # "Reconnaissance"). Normalize so cross-validation works.
    def _normalize_tactic(raw: str) -> str:
        # STIX sometimes has trailing whitespace ("initial-access ").
        words = raw.strip().replace("-", " ").split()
        if not words:
            return raw.strip()
        # Title-case every word, EXCEPT short conjunctions/articles ("and",
        # "or") which ATT&CK renders lowercase ("Command and Control").
        conjunctions = {"and", "or"}
        parts = [w.title() if w.lower() not in conjunctions else w.lower()
                 for w in words]
        return " ".join(parts)

    by_tactic: dict[str, dict[str, dict]] = {t: {} for t in _TACTIC_ORDER}
    seen_pairs: set[tuple[str, str]] = set()
    for tech_id, info in by_id.items():
        for phase in info["kill_chain_phases"]:
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            raw = phase.get("phase_name") or ""
            tactic = _normalize_tactic(raw)
            if tactic not in by_tactic:
                # ATT&CK sometimes adds new tactics before we update our order list.
                # Place them at the end so they're never silently dropped.
                by_tactic.setdefault(tactic, {})
                print(
                    f"  WARNING: unknown tactic '{tactic}' — adding at end of matrix",
                    file=sys.stderr,
                )
            key = (tactic, tech_id)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            by_tactic[tactic][tech_id] = {"id": tech_id, "name": info["name"]}

    tactics_out = []
    for tactic in list(by_tactic.keys()):
        techs = sorted(by_tactic[tactic].values(), key=lambda t: _tech_sort_key(t["id"]))
        if not techs:
            continue
        tactics_out.append({"tactic": tactic, "techniques": techs})

    # Custom order: _TACTIC_ORDER first, then any new (unknown) tactics appended.
    head = [t for t in tactics_out if t["tactic"] in _TACTIC_ORDER]
    head.sort(key=lambda t: _TACTIC_ORDER.index(t["tactic"]))
    tail = [t for t in tactics_out if t["tactic"] not in _TACTIC_ORDER]
    return head + tail, version


def _tech_sort_key(tech_id: str) -> tuple:
    """Sort techniques as T0001, T0002, ... then any sub-technique suffixes.
    Top-level techniques have no ``.`` so they sort before their children.
    """
    base, _, suffix = tech_id.partition(".")
    try:
        n = int(base[1:])
    except (ValueError, IndexError):
        n = 10_000
    return (n, suffix or "")


def _latest_attack_tag() -> str:
    """Discover the most recent ATT&CK release tag from the GitHub API.

    Returns the version number (e.g. ``"17.1"``) of the highest ``ATT&CK-v*``
    tag. Falls back to a hard-coded recent release if the API is unreachable
    so the script still works offline-ish.
    """
    try:
        req = urllib.request.Request(_GH_TAGS_API, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310  # nosemgrep: dynamic-urllib-use-detected
            tags = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        print(
            f"WARNING: could not list MITRE tags ({exc}); using ATT&CK-v18.1 fallback",
            file=sys.stderr,
        )
        return "ATT&CK-v18.1"
    versions: list[tuple[tuple[int, ...], str]] = []
    for t in tags:
        name = (t.get("name") or "").strip()
        if not name.startswith("ATT&CK-v"):
            continue
        version = name[len("ATT&CK-v"):]
        parts: list[int] = []
        for piece in version.split("."):
            try:
                parts.append(int(piece))
            except ValueError:
                parts = []
                break
        if parts:
            # The raw tag name (with `&`) is what we use in the URL path.
            versions.append((tuple(parts), name))
    if not versions:
        return "ATT&CK-v18.1"
    # Skip container-matrix releases (v19+ adds "Defense Impairment" and
    # "Stealth" containers). The TinySIEM `_TACTICS` list is the canonical
    # 14-tactic Enterprise matrix; if you point at v19 you'll see warnings
    # about dropped tactics. Override with --release explicitly if desired.
    container_versions = {(19, 0), (19, 1), (19, 2)}
    standard = [(k, tag) for k, tag in versions if k not in container_versions]
    if not standard:
        return versions[0][1]
    return standard[0][1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch MITRE ATT&CK Enterprise matrix and trim it to JSON.",
    )
    parser.add_argument(
        "--out",
        default=str(_DEFAULT_OUT),
        help="output JSON path (default: app/rules/data/mitre_enterprise.json)",
    )
    parser.add_argument(
        "--release",
        default=None,
        help="ATT&CK release version (e.g. 17.1). Default: latest from GitHub API.",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="MITRE STIX bundle URL (override only for testing).",
    )
    args = parser.parse_args()

    if args.url:
        bundle_url = args.url
        release_label = "custom"
    else:
        tag = args.release or _latest_attack_tag()
        # Args.release is just the version (e.g. "17.1"); normalize to the
        # full tag name so the URL template resolves consistently.
        if not tag.startswith("ATT&CK-v"):
            tag = f"ATT&CK-v{tag}"
        # Tag name contains `&` which must be percent-encoded in the URL path.
        encoded_tag = urllib.parse.quote(tag, safe="")
        bundle_url = _BUNDLE_TEMPLATE.format(tag=encoded_tag)
        release_label = tag[len("ATT&CK-v"):]

    bundle = _fetch_bundle(bundle_url)
    tactics, stix_version = _extract_techniques(bundle)
    unique_techs = {t["id"] for tac in tactics for t in tac["techniques"]}
    today = _dt.date.today().isoformat()

    payload = {
        "version": f"v{release_label}",
        "generated": today,
        "source": bundle_url,
        "tactics": tactics,
        "totals": {
            "tactics": len(tactics),
            "techniques": len(unique_techs),
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")
    size_kb = out_path.stat().st_size / 1024
    print(
        f"Wrote {out_path} — {payload['totals']['tactics']} tactics, "
        f"{payload['totals']['techniques']} unique techniques "
        f"({size_kb:.1f} KB, ATT&CK {payload['version']})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
