"""Run the nine consensus experiments and five governance scenarios and write JSON evidence."""

import json
from pathlib import Path

from app.consensus.experiments import all_ids, run_experiment
from app.governance import all_scenarios

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "evidence"


def main():
    experiments = OUT / "experiments"
    experiments.mkdir(parents=True, exist_ok=True)
    for experiment_id in all_ids():
        result = run_experiment(experiment_id)
        (experiments / f"{experiment_id}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"{experiment_id}: {result['observed_result']} ({result['test_result']})")
    governance = OUT / "governance"
    governance.mkdir(parents=True, exist_ok=True)
    scenarios = all_scenarios()
    (governance / "scenarios.json").write_text(json.dumps(scenarios, indent=2), encoding="utf-8")
    for scenario in scenarios:
        print(f"{scenario['id']}: {scenario.get('decision', scenario['title'])}")
    print(f"Evidence written under {OUT}")


if __name__ == "__main__":
    main()
