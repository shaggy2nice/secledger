"""`secledger-adapt` — convert a scanner's native JSON to the findings schema.

    secledger-adapt <scanner> [input.json] [-o out.json] [--run-id ID] [--target NAME]

Reads stdin when no input file is given and writes stdout when no ``-o`` is
given, so it pipes straight into ``ingest``::

    semgrep --json -o - . | secledger-adapt semgrep --target dev | secledger ingest -

The output is validated against the findings schema before it is written, so a
broken adapter fails loudly instead of producing a bad ledger.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..schema import SchemaError, validate_document
from . import available, get_adapter


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="secledger-adapt",
        description="Convert scanner output into the secledger findings schema.",
    )
    p.add_argument("scanner", choices=available(), help="source scanner")
    p.add_argument("input", nargs="?", default="-",
                   help="native scanner JSON file (default: stdin)")
    p.add_argument("-o", "--output", default="-",
                   help="findings JSON output file (default: stdout)")
    p.add_argument("--run-id", help="run id (default: current UTC timestamp)")
    p.add_argument("--target", default="", help="target name recorded on the run")
    args = p.parse_args(argv)

    try:
        raw_text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text()
        raw = json.loads(raw_text)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error reading {args.input}: {exc}", file=sys.stderr)
        return 1

    doc = get_adapter(args.scanner)(raw, run_id=args.run_id, target=args.target)

    try:
        validate_document(doc)
    except SchemaError as exc:  # pragma: no cover - guards against adapter bugs
        print(f"adapter produced an invalid document: {exc}", file=sys.stderr)
        return 2

    out = json.dumps(doc, indent=2) + "\n"
    if args.output == "-":
        sys.stdout.write(out)
    else:
        Path(args.output).write_text(out)
    print(
        f"{args.scanner}: {len(doc['findings'])} findings -> "
        f"{'stdout' if args.output == '-' else args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
