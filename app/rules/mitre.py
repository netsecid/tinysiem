from pathlib import Path

import yaml

_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def compute_coverage(rule_files: list[tuple[Path, bool]]) -> dict:
    tactic_map: dict[str, dict[str, dict]] = {t: {} for t in _TACTICS}
    for path, _is_custom in rule_files:
        try:
            data = yaml.safe_load(path.read_text())
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        tactic = data.get("mitre_tactic")
        technique = data.get("mitre_technique")
        if not tactic or not technique or tactic not in tactic_map:
            continue
        entry = tactic_map[tactic].setdefault(technique, {"count": 0, "rules": []})
        entry["count"] += 1
        entry["rules"].append(data.get("name", path.stem))
    return {
        "tactics": [
            {
                "tactic": t,
                "techniques": [
                    {"technique": tech, "count": v["count"], "rules": v["rules"]}
                    for tech, v in sorted(techniques.items())
                ],
            }
            for t, techniques in tactic_map.items()
        ]
    }
