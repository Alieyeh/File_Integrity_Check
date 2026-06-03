from __future__ import annotations

import sys
from pathlib import Path


def _ensure_local_src_on_path() -> None:
    src = Path(__file__).resolve().parent / "src"
    if src.exists():
        sys.path.insert(0, str(src))


def main() -> int:
    _ensure_local_src_on_path()
    from file_integrity_monitor.cli import main as cli_main

    args = sys.argv[1:]
    if args and args[0] in {"run", "scan", "schedule", "weekly"}:
        return cli_main(args)
    return cli_main(["run", *args])


if __name__ == "__main__":
    raise SystemExit(main())
