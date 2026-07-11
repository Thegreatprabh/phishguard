from __future__ import annotations

import time
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.text import Text

from .models import ScanResult
from .scanner import scan_html, scan_text, scan_url

console = Console()

BANNER = r"""
 ____  _     _     _     ____                     _
|  _ \| |__ (_)___| |__ / ___|_   _  __ _ _ __ __| |
| |_) | '_ \| / __| '_ \ |  _| | | |/ _` | '__/ _` |
|  __/| | | | \__ \ | | |__| | |_| | (_| | | | (_| |
|_|   |_| |_|_|___/_| |_|____/ \__,_|\__,_|_|  \__,_|
"""

SIGNATURE = "THE GREAT PRABH"


def boot_animation() -> None:
    console.clear()
    with Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Booting PhishGuard engine...", total=None)
        time.sleep(1.0)
        progress.update(task, description="Loading brand signatures...")
        time.sleep(0.7)
        progress.update(task, description="Warming up URL heuristics...")
        time.sleep(0.6)
        progress.update(task, description="Ready.")
        time.sleep(0.4)

    gradient = ["bright_cyan", "cyan", "bright_blue", "blue", "bright_blue", "cyan"]
    banner_text = Text()
    lines = BANNER.strip("\n").splitlines()
    for index, line in enumerate(lines):
        banner_text.append(line + "\n", style=f"bold {gradient[index % len(gradient)]}")

    console.print(Align.center(banner_text))
    console.print(Align.center(Text(f"by {SIGNATURE}", style="bold magenta")))
    console.print(Align.center(Text("Phishing & Fake Login Detector\n", style="italic white")))


def scanning_animation(label: str) -> None:
    with Progress(
        SpinnerColumn(style="bold yellow"),
        TextColumn("[bold yellow]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"{label}...", total=None)
        time.sleep(1.0)


def risk_style(risk: str) -> tuple[str, str, str]:
    if risk == "dangerous":
        return "bold white on red", "red", "\u2716  DANGEROUS"
    if risk == "suspicious":
        return "bold black on yellow", "yellow", "\u26a0  SUSPICIOUS"
    return "bold white on green", "green", "\u2714  SAFE"


def show_result(result: ScanResult) -> None:
    title_style, border, label = risk_style(result.risk)

    body = Text()
    body.append("Target   ", style="bold")
    body.append(f"{result.target}\n")
    body.append("Score    ", style="bold")
    body.append(f"{result.score}/100\n")
    if result.category != "clean":
        body.append("Category ", style="bold")
        brand = f" ({result.brand})" if result.brand else ""
        body.append(f"{result.category}{brand}\n")

    if result.evidence:
        body.append("\n")
        for item in sorted(result.evidence, key=lambda e: -e.score):
            body.append(f"  +{item.score:02d} ", style="bold")
            body.append(f"{item.label}: ", style="bold")
            body.append(f"{item.detail}\n")
    else:
        body.append("\nNo phishing signals detected.\n", style="dim")

    console.print(
        Panel(
            body,
            title=Text(f" {label} ", style=title_style),
            border_style=border,
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )


def show_results(result: ScanResult | list[ScanResult]) -> None:
    items = result if isinstance(result, list) else [result]
    for item in items:
        show_result(item)


def main_menu() -> str:
    console.print(
        Panel(
            "[bold cyan]1[/]  Scan a URL\n"
            "[bold cyan]2[/]  Scan Text / Message\n"
            "[bold cyan]3[/]  Scan a Local HTML File\n"
            "[bold cyan]4[/]  Exit",
            title="[bold]Main Menu[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
    )
    return Prompt.ask("[bold green]Select an option[/]", choices=["1", "2", "3", "4"], default="1")


def run_interactive() -> int:
    boot_animation()
    while True:
        choice = main_menu()

        if choice == "1":
            url = Prompt.ask("[bold]Enter URL to scan[/]").strip()
            if not url:
                continue
            scanning_animation("Analyzing URL")
            show_results(scan_url(url))

        elif choice == "2":
            text = Prompt.ask("[bold]Paste text / message[/]").strip()
            if not text:
                continue
            scanning_animation("Analyzing text")
            show_results(scan_text(text))

        elif choice == "3":
            path = Prompt.ask("[bold]Enter path to HTML file[/]").strip()
            try:
                html = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                console.print(f"[bold red]Could not read file:[/] {exc}")
                continue
            scanning_animation("Analyzing HTML")
            show_results(scan_html(html))

        else:
            console.print(Align.center(Text("Stay safe. Goodbye!\n", style="bold cyan")))
            return 0

        console.print()
