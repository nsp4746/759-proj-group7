import argparse
import json
import pathlib
import pprint
import textwrap
import zipfile
from collections import Counter
from functools import lru_cache
from typing import Iterable, Optional


def format_finding_as_prompt(record: dict) -> str:
    """Formats a single finding record into a detailed LLM prompt."""

    prompt = f"""You’re triaging shell-command injection alerts.

Rule: {record.get('rule_id', 'N/A')}
Score: {record.get('score', 'N/A')}
File: {record.get('sink', {}).get('uri', 'N/A')}
Line: {record.get('sink', {}).get('start_line', 'N/A')}

Sink (where the command is executed):
```
{record.get('sink', {}).get('snippet', 'No snippet available.')}
```

Source (where the input originates):
```
{record.get('source', {}).get('snippet', 'No snippet available.')}
```

Taint Path (data flow from source to sink):
"""

    path_steps = record.get('path', [])
    if not path_steps:
        prompt += "No data flow path available.\n"
    else:
        for i, step in enumerate(path_steps):
            message = step.get('message', 'Step')
            location = step.get('location', {})
            uri = location.get('uri', 'N/A')
            line = location.get('start_line', 'N/A')
            prompt += f"{i+1}. {message} at {uri}:{line}\n"

    prompt += textwrap.dedent("""
    Please answer these questions:
    1. Does the command execute user-controlled or environment-derived input?
    2. Is there any sanitization or validation of the input?
    3. Is the execution path from source to sink reachable in a realistic scenario?
    4. Are there any other constraints or conditions that might mitigate the risk?

    Return a JSON response with your verdict, confidence, and a brief reason. The reason must reference details from the code snippets.
    {
        "verdict": "malicious|benign|unsure",
        "confidence": "high|medium|low",
        "reason": "..."
    }
    """)

    return prompt



def load_json(path: str | pathlib.Path) -> dict:
    path = pathlib.Path(path)
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise SystemExit(f"File not found: {path}")


def sarif_summary(path: str, limit: int) -> None:
    data = load_json(path)
    runs = data.get("runs", [])
    if not runs:
        print("No runs in SARIF file.")
        return
    run = runs[0]
    results = run.get("results", [])
    print(f"Runs: {len(runs)} | Results: {len
    (results)}")
    counts = Counter(res.get("ruleId", "<unknown>") for res in results)
    print("Rule counts:")
    for rule_id, count in counts.most_common():
        print(f"  {rule_id}: {count}")
    print(f"\nFirst {min(limit, len(results))} results:")
    for idx, res in enumerate(results[:limit]):
        rule = res.get("ruleId", "<unknown>")
        message = res.get("message", {}).get("text", "").strip()
        loc = _format_sarif_location(res)
        print(f"[{idx}] {rule} @ {loc}")
        if message:
            print(f"    {message}")


def sarif_result(path: str, index: int) -> None:
    data = load_json(path)
    runs = data.get("runs", [])
    if not runs:
        raise SystemExit("No runs in SARIF file.")
    results = runs[0].get("results", [])
    if not (0 <= index < len(results)):
        raise SystemExit(f"Result index {index} out of range (0..{len(results)-1}).")
    res = results[index]
    pprint.pprint(res)


def _format_sarif_location(res: dict) -> str:
    locations = res.get("locations") or []
    if not locations:
        return "<no location>"
    physical = locations[0].get("physicalLocation", {})
    file_path = physical.get("artifactLocation", {}).get("uri", "<file>")
    region = physical.get("region", {})
    line = region.get("startLine")
    if line is None:
        return file_path
    return f"{file_path}:{line}"


def bqrs_summary(path: str) -> None:
    data = load_json(path)
    tables = [
        (name, table) for name, table in data.items() if isinstance(table, dict) and "tuples" in table
    ]
    if not tables:
        print("No tables found in decoded BQRS JSON.")
        return
    print(f"Tables: {len(tables)}")
    for name, table in tables:
        columns = table.get("columns", [])
        print(f"- {name}: {len(table.get('tuples', []))} rows | columns: {', '.join(_col_name(c) for c in columns)}")


def bqrs_table(path: str, table_name: str, limit: int) -> None:
    data = load_json(path)
    try:
        table = data[table_name]
    except KeyError:
        available = ", ".join(sorted(k for k in data if isinstance(data[k], dict) and "tuples" in data[k]))
        raise SystemExit(f"Table '{table_name}' not found. Available tables: {available}")
    tuples = table.get("tuples", [])
    print(f"{table_name}: {len(tuples)} rows")
    for row in tuples[:limit]:
        pprint.pprint(row)


def _col_name(col: dict) -> str:
    base = col.get("name") or col.get("kind", "<col>")
    kind = col.get("kind")
    return f"{base}:{kind}" if kind else base


class SourceArchive:
    """Helper for retrieving snippets from the database source archive."""

    def __init__(self, zip_path: str | pathlib.Path):
        self.zip_path = pathlib.Path(zip_path)
        if not self.zip_path.exists():
            raise SystemExit(f"Source archive not found: {self.zip_path}")
        self._zip = zipfile.ZipFile(self.zip_path)
        self._cache: dict[str, Optional[str]] = {}

    def read_context(self, uri: Optional[str], line: Optional[int], context: int) -> Optional[dict]:
        if not uri or not line:
            return None
        entry = self._resolve(uri)
        if entry is None:
            return None
        lines = self._read_lines(entry)
        index = max(line - 1, 0)
        start = max(index - context, 0)
        end = min(index + context, len(lines) - 1)
        snippet_lines = []
        for lineno in range(start, end + 1):
            prefix = f"{lineno + 1:>5}: "
            snippet_lines.append(prefix + lines[lineno].rstrip("\n"))
        return {
            "uri": uri,
            "zip_entry": entry,
            "line": line,
            "snippet": "\n".join(snippet_lines),
        }

    def _resolve(self, uri: str) -> Optional[str]:
        if uri in self._cache:
            return self._cache[uri]
        matches = [name for name in self._zip.namelist() if name.endswith(uri)]
        entry = min(matches, key=len) if matches else None
        self._cache[uri] = entry
        return entry

    @lru_cache(maxsize=256)
    def _read_lines(self, entry: str) -> list[str]:
        with self._zip.open(entry) as handle:
            data = handle.read().decode("utf-8", errors="replace")
        return data.splitlines()


def extract_context_records(
    sarif_path: str, src_zip: str, context: int, limit: Optional[int] = None
) -> list[dict]:
    sarif = load_json(sarif_path)
    runs = sarif.get("runs", [])
    if not runs:
        raise SystemExit("SARIF file has no runs.")
    results = runs[0].get("results", [])
    archive = SourceArchive(src_zip)
    records: list[dict] = []
    for idx, result in enumerate(results):
        if limit is not None and idx >= limit:
            break
        sink_loc = _first_physical_location(result.get("locations", []))
        source_loc = _first_physical_location(result.get("relatedLocations", []))
        record = {
            "result_index": idx,
            "rule_id": result.get("ruleId"),
            "message": result.get("message", {}).get("text"),
            "score": (result.get("properties") or {}).get("score"),
            "sink": _location_payload(sink_loc, archive, context),
            "source": _location_payload(source_loc, archive, context),
            "path": _code_flow_steps(result.get("codeFlows", []), archive, context),
        }
        records.append(record)
    return records


def _first_physical_location(items: Iterable[dict] | None) -> Optional[dict]:
    if not items:
        return None
    for item in items:
        if not isinstance(item, dict):
            continue
        if "physicalLocation" in item:
            return item["physicalLocation"]
        loc = item.get("location")
        if isinstance(loc, dict) and "physicalLocation" in loc:
            return loc["physicalLocation"]
    return None


def _location_payload(location: Optional[dict], archive: SourceArchive, context: int) -> Optional[dict]:
    if not location:
        return None
    artifact = location.get("artifactLocation", {})
    region = location.get("region", {})
    uri = artifact.get("uri")
    snippet = archive.read_context(uri, region.get("startLine"), context)
    payload = {
        "uri": uri,
        "start_line": region.get("startLine"),
        "start_column": region.get("startColumn"),
        "end_line": region.get("endLine"),
        "end_column": region.get("endColumn"),
        "snippet": snippet["snippet"] if snippet else None,
    }
    return payload


def _code_flow_steps(
    code_flows: Optional[list], archive: SourceArchive, context: int
) -> list[dict]:
    steps: list[dict] = []
    if not code_flows:
        return steps
    for flow in code_flows:
        for thread in flow.get("threadFlows", []):
            for node in thread.get("locations", []):
                loc = node.get("location", {})
                message = (loc.get("message") or {}).get("text")
                physical = loc.get("physicalLocation")
                payload = _location_payload(physical, archive, context)
                steps.append({"message": message, "location": payload})
    return steps


def generate_prompts(
    sarif_path: str,
    src_zip: str,
    output_path: str,
    context: int,
    limit: Optional[int] = None,
) -> None:
    """Generate LLM prompts and write them to a file."""
    records = extract_context_records(sarif_path, src_zip, context, limit)
    output = pathlib.Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    prompts = [format_finding_as_prompt(rec) for rec in records]
    # We'll write all prompts separated by a clear boundary
    output.write_text("\n\n---\n\n".join(prompts), encoding="utf-8")
    print(f"Wrote {len(prompts)} prompts to {output}")



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect SARIF and decoded BQRS JSON files.")
    sub = parser.add_subparsers(dest="command", required=True)

    sarif_sum = sub.add_parser("sarif-summary", help="Print counts and sample results from a SARIF file.")
    sarif_sum.add_argument("path")
    sarif_sum.add_argument("--limit", type=int, default=5, help="Number of sample results to display.")

    sarif_one = sub.add_parser("sarif-result", help="Show a single SARIF result by index.")
    sarif_one.add_argument("path")
    sarif_one.add_argument("--index", type=int, default=0)

    bqrs_sum = sub.add_parser("bqrs-summary", help="List tables in decoded BQRS JSON.")
    bqrs_sum.add_argument("path")

    bqrs_tbl = sub.add_parser("bqrs-table", help="Display rows from a decoded BQRS table.")
    bqrs_tbl.add_argument("path")
    bqrs_tbl.add_argument("--table", default="#select")
    bqrs_tbl.add_argument("--limit", type=int, default=5)

    extract = sub.add_parser(
        "extract-context",
        help="Create JSONL records combining SARIF findings with source snippets for LLM triage.",
    )
    extract.add_argument("--sarif", required=True, help="Path to SARIF results file.")
    extract.add_argument("--src-zip", required=True, help="Path to database src.zip.")
    extract.add_argument("--output", required=True, help="Destination JSONL file.")
    extract.add_argument("--context", type=int, default=5, help="Lines of context around each location.")
    extract.add_argument("--limit", type=int, help="Limit number of findings processed.")

    prompts = sub.add_parser(
        "generate-prompts",
        help="Generate LLM prompts for triaging findings.",
    )
    prompts.add_argument("--sarif", required=True, help="Path to SARIF results file.")
    prompts.add_argument("--src-zip", required=True, help="Path to database src.zip.")
    prompts.add_argument("--output", required=True, help="Destination file for prompts.")
    prompts.add_argument("--context", type=int, default=5, help="Lines of context around each location.")
    prompts.add_argument("--limit", type=int, help="Limit number of findings processed.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "sarif-summary":
        sarif_summary(args.path, args.limit)
    elif args.command == "sarif-result":
        sarif_result(args.path, args.index)
    elif args.command == "bqrs-summary":
        bqrs_summary(args.path)
    elif args.command == "bqrs-table":
        bqrs_table(args.path, args.table, args.limit)
    elif args.command == "extract-context":
        records = extract_context_records(args.sarif, args.src_zip, args.context, args.limit)
        output_path = pathlib.Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            for record in records:
                json.dump(record, handle, ensure_ascii=False)
                handle.write("\n")
        print(f"Wrote {len(records)} records to {output_path}")
    elif args.command == "generate-prompts":
        generate_prompts(args.sarif, args.src_zip, args.output, args.context, args.limit)
    else:
        parser.error(f"Unknown command {args.command}")


if __name__ == "__main__":
    main()
