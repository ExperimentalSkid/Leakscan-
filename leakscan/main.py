"""Leakscan command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from . import __version__
from .bootstrap import CatalogBootstrapper
from .config import AppConfig, generate_queries, load_config, load_dotenv
from .crawler import Crawler
from .database import CaseDatabase
from .providers import build_providers
from .reporting import export_reports, prepare_output, write_manifest
from .search import SearchEngine
from .verifier import verify_candidates
from .wizard import WizardCancelled, run_wizard

LOG = logging.getLogger("leakscan")

SEARCH_PROFILES = {
    "focused": (15, 15, 5, 1),
    "balanced": (60, 45, 10, 3),
    "broad": (120, 60, 20, 5),
}


def build_parser() -> argparse.ArgumentParser:
    default_settings = Path(__file__).resolve().with_name("default_settings.yaml")
    parser = argparse.ArgumentParser(
        prog="leakscan",
        description=(
            "Catalog-first public-reference discovery and metadata-only candidate verification. "
            "Run without arguments for a guided scan."
        ),
    )
    parser.add_argument(
        "command",
        choices=("wizard", "bootstrap", "search", "crawl", "verify", "report", "all"),
        help="Run 'wizard' (or run leakscan with no arguments) for guided setup",
    )
    parser.add_argument("--case", help="YAML case file containing target fingerprints and optional seed listings")
    parser.add_argument("--settings", default=str(default_settings), help="Generic YAML runtime settings")
    parser.add_argument("--output", help="Case output directory")
    parser.add_argument("--max-depth", type=int)
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--max-pages", type=int)
    parser.add_argument("--max-pages-per-domain", type=int)
    parser.add_argument("--max-html-bytes", type=int)
    parser.add_argument("--per-host-delay", type=float)
    parser.add_argument("--retry-count", type=int)
    parser.add_argument("--provider", action="append", help="Provider name; repeat to select several")
    parser.add_argument(
        "--search-profile",
        choices=tuple(SEARCH_PROFILES),
        help="Discovery breadth: focused, balanced, or broad (overrides search request/plateau settings)",
    )
    parser.add_argument(
        "--max-provider-requests",
        type=int,
        help="Maximum actual requests per provider across this case; 0 disables the ceiling",
    )
    parser.add_argument(
        "--max-result-pages-per-query",
        type=int,
        help="Maximum native result pages traversed for one provider query",
    )
    parser.add_argument("--resume", action="store_true", help="Continue from existing SQLite state")
    parser.add_argument("--dry-run", action="store_true", help="Generate the plan and case structure without network requests")
    parser.add_argument("--ignore-robots", action="store_true", help="Disable robots.txt checks")
    parser.add_argument("--allow-private-networks", action="store_true", help="Permit explicitly supplied private/local hosts")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _apply_overrides(config, args) -> None:
    mapping = {
        "max_depth": "max_depth", "concurrency": "concurrency", "timeout": "timeout_seconds",
        "max_pages": "max_pages", "max_pages_per_domain": "max_pages_per_domain",
        "max_html_bytes": "max_html_bytes", "per_host_delay": "per_host_delay_seconds",
        "retry_count": "retry_count",
    }
    for argument, attribute in mapping.items():
        value = getattr(args, argument)
        if value is not None:
            setattr(config.crawl, attribute, value)
    if args.ignore_robots:
        config.crawl.respect_robots_txt = False
    if args.allow_private_networks:
        config.safety.reject_private_networks = False
    if args.search_profile:
        maximum, minimum, stale, result_pages = SEARCH_PROFILES[args.search_profile]
        config.search.max_queries_per_provider = maximum
        config.search.minimum_queries_before_plateau = minimum
        config.search.stop_after_stale_queries = stale
        config.search.max_result_pages_per_query = result_pages
    if args.max_provider_requests is not None:
        if args.max_provider_requests < 0:
            raise ValueError("--max-provider-requests must be zero or greater")
        config.search.max_queries_per_provider = args.max_provider_requests
    if args.max_result_pages_per_query is not None:
        if args.max_result_pages_per_query < 1:
            raise ValueError("--max-result-pages-per-query must be at least one")
        config.search.max_result_pages_per_query = args.max_result_pages_per_query


def _configure_logging(output: Path, verbose: bool) -> None:
    output.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)sZ %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(output / "investigation.log", encoding="utf-8")],
        force=True,
    )
    logging.Formatter.converter = __import__("time").gmtime


def _provider_availability(config: AppConfig) -> dict[str, str]:
    output = {}
    for name, provider in build_providers().items():
        provider.configure(config)
        available, reason = provider.available()
        output[name] = "available" if available else reason
    return output


def _mark_current_pivots_searched(database: CaseDatabase) -> None:
    for item in database.pending_pivots():
        database.mark_pivot_searched(item["pivot_type"], item["value"])


async def _execute(args) -> int:
    root = Path(args.settings).expanduser().resolve().parent
    load_dotenv(root / ".env")
    config = load_config(args.settings, args.case, args.output)
    _apply_overrides(config, args)
    prepare_output(config)
    _configure_logging(config.output_dir, args.verbose)
    selected_providers = args.provider or config.search.providers
    availability = _provider_availability(config)
    if args.dry_run:
        write_manifest(config, args.command, selected_providers, True, availability)
        LOG.info("[DRY-RUN] case=%s", config.case.name)
        for seed in config.case.seeds:
            LOG.info("[CATALOG-PLAN] adapter=%s source=%s url=%s", seed.adapter, seed.source, seed.url)
        LOG.info(
            "[DRY-RUN] initial_queries=%s providers=%s output=%s",
            len(generate_queries(config)), ",".join(selected_providers), config.output_dir,
        )
        for name in selected_providers:
            LOG.info("[PROVIDER] %s: %s", name, availability.get(name, "unknown"))
        return 0

    database_path = config.output_dir / "state.sqlite3"
    existed = database_path.exists()
    database = CaseDatabase(database_path)
    try:
        if (
            existed
            and args.command in {"bootstrap", "search", "crawl", "all"}
            and not args.resume
            and database.stats()["findings"]
        ):
            raise RuntimeError(f"case state already exists at {database_path}; pass --resume to continue")

        if args.command == "bootstrap":
            await CatalogBootstrapper(config, database).run()
        elif args.command == "search":
            await CatalogBootstrapper(config, database).run()
            await SearchEngine(config, database).run(
                generate_queries(config, database.pivot_map()), selected_providers
            )
            _mark_current_pivots_searched(database)
        elif args.command == "crawl":
            await CatalogBootstrapper(config, database).run()
            await Crawler(config, database).run()
        elif args.command == "verify":
            await verify_candidates(config, database)
        elif args.command == "report":
            export_reports(config, database)
        elif args.command == "all":
            await CatalogBootstrapper(config, database).run()
            search = SearchEngine(config, database)
            await search.run(
                generate_queries(config, database.pivot_map()),
                selected_providers,
                verify_immediately=True,
            )
            _mark_current_pivots_searched(database)
            await Crawler(config, database).run()
            rounds = 0
            while rounds < config.search.max_pivot_rounds and database.visited_count() < config.crawl.max_pages:
                pivots = database.pending_pivots()[: config.search.max_pivots_per_round]
                if not pivots:
                    break
                await search.run(
                    generate_queries(config, database.pivot_map()),
                    selected_providers,
                    verify_immediately=True,
                )
                _mark_current_pivots_searched(database)
                await Crawler(config, database).run()
                rounds += 1
            await verify_candidates(config, database, skip_checked=True)
            export_reports(config, database)
        write_manifest(config, args.command, selected_providers, False, availability, database)
        LOG.info("[DONE] %s", database.stats())
        if args.command in {"all", "report"}:
            LOG.info("[REPORT] %s", config.output_dir / "reports" / "analyst_summary.md")
        return 0
    finally:
        database.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        if not raw_args:
            raw_args = ["wizard"]
        args = parser.parse_args(raw_args)
        if args.command == "wizard":
            args = parser.parse_args(run_wizard())
        if not args.case:
            parser.error("--case is required for advanced commands; run 'leakscan' for guided setup")
        return asyncio.run(_execute(args))
    except WizardCancelled as exc:
        print(str(exc), file=sys.stderr)
        return 0
    except EOFError:
        print("No interactive input was available. Run 'leakscan --help' for advanced usage.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if "args" in locals() and args.case and args.output:
            profile = f" --search-profile {args.search_profile}" if args.search_profile else ""
            print(
                "Interrupted safely. Resume with:\n"
                f"leakscan all --resume --case \"{args.case}\" --output \"{args.output}\"{profile}",
                file=sys.stderr,
            )
        else:
            print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary converts failures into a stable exit code.
        LOG.error("%s: %s", type(exc).__name__, exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
