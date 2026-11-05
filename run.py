"""Single-command launcher:  python run.py [--port 8501] [--rebuild]

Builds the seeded synthetic demo workspace on first run (data, baselines, model, alerts,
evaluation), then starts the Streamlit dashboard bound to localhost.
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8501)
    ap.add_argument("--rebuild", action="store_true", help="regenerate the demo dataset and re-run the pipeline")
    ap.add_argument("--no-ui", action="store_true", help="only prepare the data, do not start the dashboard")
    a = ap.parse_args()

    from insider import db
    from insider.cli import init_demo
    if a.rebuild or not db.workspace_path("demo").exists():
        print("Preparing demo workspace (generate data -> baselines -> rules -> ML -> correlation -> risk -> evaluation)...")
        r = init_demo("demo")
        print(f"  {r['events']:,} events, {r['alerts']} alerts -> {r['path']}")
    else:
        db.set_active_workspace(db.get_active_workspace())
    if a.no_ui:
        return 0
    print(f"Starting dashboard at http://127.0.0.1:{a.port}  (Ctrl+C to stop)")
    return subprocess.call([sys.executable, "-m", "streamlit", "run", str(ROOT / "dashboard" / "app.py"),
                            "--server.address", "127.0.0.1", "--server.port", str(a.port),
                            "--server.headless", "true", "--browser.gatherUsageStats", "false"], cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
