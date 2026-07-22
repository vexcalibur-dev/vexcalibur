from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_renovate_scans_the_csaf_validator_package() -> None:
    configuration = json.loads((ROOT / "renovate.json").read_text(encoding="utf-8"))
    tool_versions = dict(
        line.split(maxsplit=1)
        for line in (ROOT / ".tool-versions").read_text(encoding="utf-8").splitlines()
    )

    assert configuration["ignorePaths"] == [
        "**/node_modules/**",
        "**/bower_components/**",
        "**/vendor/**",
    ]
    assert configuration["prHourlyLimit"] == 2
    assert configuration["enabledManagers"] == ["github-actions", "npm", "pep621"]
    assert configuration["constraints"] == {"uv": tool_versions["uv"]}
    assert configuration["vulnerabilityAlerts"] == {"enabled": False}
    assert configuration["lockFileMaintenance"] == {"enabled": True}
    assert configuration["packageRules"] == [
        {
            "description": "Automerge minor and patch updates after required checks pass.",
            "matchManagers": [
                "npm",
            ],
            "matchUpdateTypes": ["minor", "patch"],
            "automerge": True,
        }
    ]
