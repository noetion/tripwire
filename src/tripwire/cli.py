from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from tripwire.adapters.agentdojo import load_taxonomy
from tripwire.corpus import build_corpus, inventory
from tripwire.evaluation import evaluate_corpus, run_rule_tests, verify_repository, write_result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tripwire")
    subcommands = parser.add_subparsers(dest="command", required=True)

    corpus = subcommands.add_parser("corpus")
    corpus_subcommands = corpus.add_subparsers(dest="corpus_command", required=True)
    inventory_parser = corpus_subcommands.add_parser("inventory")
    _add_source_arguments(inventory_parser)
    build_parser = corpus_subcommands.add_parser("build")
    _add_source_arguments(build_parser)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--source-url", default="https://github.com/ethz-spylab/agentdojo")
    build_parser.add_argument("--source-revision", required=True)
    build_parser.add_argument("--built-at", default="2026-08-03T00:00:00Z")

    rule = subcommands.add_parser("rule")
    rule_subcommands = rule.add_subparsers(dest="rule_command", required=True)
    test_parser = rule_subcommands.add_parser("test")
    test_parser.add_argument("rule_path", type=Path)

    evaluate_parser = subcommands.add_parser("evaluate")
    evaluate_parser.add_argument("--rule", type=Path, required=True)
    evaluate_parser.add_argument("--corpus", type=Path, required=True)
    evaluate_parser.add_argument(
        "--split", choices=["development", "holdout", "all"], default="all"
    )
    evaluate_parser.add_argument("--output", type=Path, required=True)

    subcommands.add_parser("verify")
    report = subcommands.add_parser("report")
    report_subcommands = report.add_subparsers(dest="report_command", required=True)
    readme_parser = report_subcommands.add_parser("readme")
    readme_parser.add_argument("--result", type=Path, required=True)
    readme_parser.add_argument("--output", type=Path, default=Path("README.md"))
    return parser


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument(
        "--taxonomy", type=Path, default=Path("config/agentdojo-banking-tools.yaml")
    )
    parser.add_argument("--attack-type", default="tool_knowledge")
    parser.add_argument("--include-benign", action=argparse.BooleanOptionalAction, default=True)


def _selected_paths(source: Path, attack_type: str, include_benign: bool) -> list[Path]:
    selected: list[Path] = []
    for path in source.rglob("*.json"):
        if path.parent.name == attack_type or include_benign and path.parent.name == "none":
            selected.append(path)
    return selected


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "corpus":
        source = args.source.resolve()
        taxonomy = load_taxonomy(args.taxonomy)
        paths = _selected_paths(source, args.attack_type, args.include_benign)
        if args.corpus_command == "inventory":
            inventory_result = inventory(paths, taxonomy, source_root=source)
            print(json.dumps(as_inventory_data(inventory_result), indent=2, sort_keys=True))
            return 0
        if args.corpus_command == "build":
            build_result = build_corpus(
                paths,
                taxonomy,
                source_root=source,
                output=args.output,
                source_url=args.source_url,
                source_revision=args.source_revision,
                built_at=args.built_at,
            )
            print(json.dumps(as_build_data(build_result), indent=2, sort_keys=True))
            return 0
    if args.command == "rule" and args.rule_command == "test":
        from tripwire.core.rules import load_rule

        rule = load_rule(args.rule_path)
        positive, negative = run_rule_tests(rule, root=Path.cwd())
        print(f"{rule.rule_id}: {positive} positive and {negative} negative fixtures passed")
        return 0
    if args.command == "evaluate":
        from tripwire.core.rules import load_rule

        evaluation_result = evaluate_corpus(load_rule(args.rule), args.corpus, split=args.split)
        write_result(evaluation_result, args.output)
        print(f"Wrote reproducible result to {args.output}")
        return 0
    if args.command == "verify":
        print(verify_repository(Path.cwd()))
        return 0
    if args.command == "report" and args.report_command == "readme":
        from tripwire.reporting import render_readme

        raw = json.loads(args.result.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("result root must be an object")
        args.output.write_text(render_readme(raw), encoding="utf-8")
        print(f"Generated {args.output} from {args.result}")
        return 0
    return 2


def as_inventory_data(result: object) -> dict[str, object]:
    from tripwire.corpus import CorpusInventory

    assert isinstance(result, CorpusInventory)
    return {
        "negative": result.negative,
        "positive": result.positive,
        "total": result.total,
        "unknown": result.unknown,
        "unknown_reasons": list(result.unknown_reasons),
    }


def as_build_data(result: object) -> dict[str, object]:
    from tripwire.corpus import CorpusBuildResult

    assert isinstance(result, CorpusBuildResult)
    return {
        **as_inventory_data(result.inventory),
        "development": {
            "positive": result.development_positive,
            "negative": result.development_negative,
        },
        "holdout": {"positive": result.holdout_positive, "negative": result.holdout_negative},
        "corpus_sha256": result.corpus_sha256,
        "split_sha256": result.split_sha256,
    }


if __name__ == "__main__":
    raise SystemExit(main())
