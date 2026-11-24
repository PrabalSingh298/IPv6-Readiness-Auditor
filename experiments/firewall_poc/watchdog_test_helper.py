import argparse
import os
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-file")
    parser.add_argument("--recovery-file")
    args = parser.parse_args()

    count_file = os.environ.get("WATCHDOG_TEST_HELPER_COUNT")
    if count_file:
        path = Path(count_file)
        count = int(path.read_text(encoding="utf-8")) if path.is_file() else 0
        path.write_text(str(count + 1), encoding="utf-8")

    log_file = os.environ.get("WATCHDOG_TEST_HELPER_LOG")
    if log_file:
        with Path(log_file).open("a", encoding="utf-8") as handle:
            handle.write(
                f"{datetime.now(timezone.utc).isoformat()} helper state={args.state_file}\n"
            )

    return int(os.environ.get("WATCHDOG_TEST_HELPER_EXIT", "0"))


if __name__ == "__main__":
    raise SystemExit(main())
