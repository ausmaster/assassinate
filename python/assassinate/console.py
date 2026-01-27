"""Rich console configuration for beautiful terminal output.

Provides a centralized Console instance and helper functions for
consistent styling across all Assassinate classes.

Example:
    >>> from assassinate.console import console, print_module, print_session
    >>> console.print("[green]Success![/green]")
    >>> print_module(module)  # Rich formatted module info
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

if TYPE_CHECKING:
    pass

# Global console instance - auto-detects terminal width
console = Console()

# =============================================================================
# Theme Colors (consistent across all output)
# =============================================================================

THEME = {
    "title": "bold white",
    "subtitle": "dim",
    "success": "bold green",
    "error": "bold red",
    "warning": "bold yellow",
    "info": "bold blue",
    "dim": "dim",
    # Module-specific
    "rank_excellent": "bold green",
    "rank_great": "green",
    "rank_good": "yellow",
    "rank_normal": "white",
    "rank_low": "dim",
    # Options
    "option_name": "cyan",
    "option_type": "magenta",
    "option_value": "yellow",
    "option_default": "dim yellow",
    "option_required": "bold red",
    "option_desc": "dim",
    # Session/Kill
    "alive": "bold green",
    "dead": "bold red",
    "confirmed": "bold green",
    "lost": "bold red",
}


def get_rank_style(rank: str) -> str:
    """Get the style for a rank string."""
    rank_lower = rank.lower() if rank else "normal"
    return THEME.get(f"rank_{rank_lower}", THEME["rank_normal"])


# =============================================================================
# Module Printing
# =============================================================================


def print_module(
    fullname: str,
    module_type: str,
    rank: str,
    description: str,
    platform: Optional[List[str]] = None,
    arch: Optional[List[str]] = None,
    options_schema: Optional[Dict[str, Dict]] = None,
    options_values: Optional[Dict[str, Any]] = None,
    references: Optional[List[str]] = None,
    authors: Optional[List[str]] = None,
    full: bool = False,
) -> None:
    """Print a beautifully formatted module summary.

    Args:
        fullname: Full module path
        module_type: Module type (exploit, auxiliary, etc.)
        rank: Module rank
        description: Module description
        platform: Target platforms
        arch: Target architectures
        options_schema: Options schema from module.options.schema()
        options_values: Current option values
        references: Module references (CVEs, URLs, etc.)
        authors: Module authors
        full: If True, show all references/authors without truncation
    """
    # Build subtitle with metadata
    rank_style = get_rank_style(rank)
    subtitle_parts = [
        f"[{rank_style}]{rank.upper()}[/{rank_style}]",
        f"[dim]{module_type.upper()}[/dim]",
    ]
    if platform:
        subtitle_parts.append(f"[dim]Platform: {', '.join(platform[:3])}[/dim]")
    if arch:
        subtitle_parts.append(f"[dim]Arch: {', '.join(arch[:3])}[/dim]")

    subtitle = "  |  ".join(subtitle_parts)

    # Build content
    content_parts = []

    # Description
    if description:
        content_parts.append(Text(description.strip(), style="white"))
        content_parts.append(Text(""))

    # Options table
    if options_schema:
        options_table = Table(
            box=box.SIMPLE,
            expand=True,
            show_header=True,
            header_style="bold",
            padding=(0, 1),
        )
        options_table.add_column("Option", style=THEME["option_name"], no_wrap=True)
        options_table.add_column("Type", style=THEME["option_type"], width=10)
        options_table.add_column("Current Value", style=THEME["option_value"])
        options_table.add_column("Description", style=THEME["option_desc"], ratio=2)

        # Sort: required first, then alphabetical
        sorted_opts = sorted(
            options_schema.items(),
            key=lambda x: (not x[1].get("required", False), x[0])
        )

        for name, info in sorted_opts:
            is_required = info.get("required", False)
            opt_type = info.get("type", "string")
            default = info.get("default", "")
            desc = info.get("desc", "")
            current = options_values.get(name, "") if options_values else ""

            # Format name with required indicator
            name_display = f"[bold red]*[/bold red]{name}" if is_required else name

            # Format value
            if current:
                value_display = f'"{current}"'
            elif default:
                value_display = f'[dim](default: "{default}")[/dim]'
            else:
                value_display = "[dim](not set)[/dim]"

            # Truncate description for table (full text in tooltip would be nice)
            desc_display = desc[:80] + "..." if len(desc) > 80 else desc

            options_table.add_row(name_display, opt_type, value_display, desc_display)

        content_parts.append(Text("\n[bold]Options:[/bold]", style="white"))
        content_parts.append(options_table)

    # References
    if references:
        ref_limit = None if full else 8
        refs_to_show = references[:ref_limit]
        ref_text = "\n[bold]References:[/bold]\n"
        for ref in refs_to_show:
            # Color CVEs green, URLs blue
            if "CVE" in ref.upper():
                ref_text += f"  [green]• {ref}[/green]\n"
            elif ref.startswith("URL-") or "http" in ref.lower():
                ref_text += f"  [blue]• {ref}[/blue]\n"
            else:
                ref_text += f"  [dim]• {ref}[/dim]\n"
        if not full and len(references) > 8:
            ref_text += f"  [dim]... and {len(references) - 8} more[/dim]\n"
        content_parts.append(Text.from_markup(ref_text))

    # Authors
    if authors:
        auth_limit = None if full else 5
        auths_to_show = authors[:auth_limit]
        auth_text = "[bold]Authors:[/bold] " + ", ".join(auths_to_show)
        if not full and len(authors) > 5:
            auth_text += f" [dim](+{len(authors) - 5} more)[/dim]"
        content_parts.append(Text.from_markup(auth_text))

    # Combine all content
    from rich.console import Group
    content = Group(*content_parts)

    # Print panel
    console.print(Panel(
        content,
        title=f"[bold]{fullname}[/bold]",
        subtitle=subtitle,
        border_style="blue",
        expand=True,
        padding=(1, 2),
    ))


# =============================================================================
# Session Printing
# =============================================================================


def print_session(
    sid: int,
    session_type: str,
    host: str,
    port: int,
    alive: bool,
    via_exploit: Optional[str] = None,
    via_payload: Optional[str] = None,
    tunnel_peer: Optional[str] = None,
    info: Optional[str] = None,
    meterpreter_info: Optional[Dict[str, Any]] = None,
    full: bool = False,
) -> None:
    """Print a beautifully formatted session summary.

    Args:
        sid: Session ID
        session_type: Type (shell, meterpreter, etc.)
        host: Target host
        port: Target port
        alive: Whether session is alive
        via_exploit: Exploit that created session
        via_payload: Payload used
        tunnel_peer: Tunnel peer address
        info: Session info string
        meterpreter_info: Dict with user, computer, os, pid, etc.
        full: Reserved for future use
    """
    _ = full  # Reserved

    status_style = THEME["alive"] if alive else THEME["dead"]
    status_text = "ALIVE" if alive else "DEAD"

    # Build content
    content_parts = []

    # Status and target
    content_parts.append(Text.from_markup(
        f"[bold]Status:[/bold] [{status_style}]{status_text}[/{status_style}]\n"
        f"[bold]Target:[/bold] {host}:{port}"
    ))

    if tunnel_peer:
        content_parts.append(Text.from_markup(f"\n[bold]Tunnel:[/bold] {tunnel_peer}"))

    if info:
        content_parts.append(Text.from_markup(f"\n[bold]Info:[/bold] {info}"))

    # Attack vector
    if via_exploit or via_payload:
        vector_text = "\n\n[bold]Attack Vector:[/bold]"
        if via_exploit:
            vector_text += f"\n  Exploit: [cyan]{via_exploit}[/cyan]"
        if via_payload:
            vector_text += f"\n  Payload: [yellow]{via_payload}[/yellow]"
        content_parts.append(Text.from_markup(vector_text))

    # Meterpreter info
    if meterpreter_info:
        meter_text = "\n\n[bold]Meterpreter Info:[/bold]"
        if meterpreter_info.get("user"):
            meter_text += f"\n  User: [green]{meterpreter_info['user']}[/green]"
        if meterpreter_info.get("pid"):
            meter_text += f"\n  PID: {meterpreter_info['pid']}"
        if meterpreter_info.get("computer"):
            meter_text += f"\n  Computer: {meterpreter_info['computer']}"
        if meterpreter_info.get("os"):
            meter_text += f"\n  OS: {meterpreter_info['os']}"
        content_parts.append(Text.from_markup(meter_text))

    from rich.console import Group
    content = Group(*content_parts)

    console.print(Panel(
        content,
        title=f"[bold]Session #{sid}[/bold]",
        subtitle=f"[{status_style}]{session_type.upper()}[/{status_style}]",
        border_style="green" if alive else "red",
        expand=True,
        padding=(1, 2),
    ))


# =============================================================================
# Kill Printing
# =============================================================================


def print_kill(
    kill_id: int,
    kill_type: str,
    host: str,
    port: int,
    confirmed: bool,
    via_exploit: Optional[str] = None,
    via_payload: Optional[str] = None,
    vulns: Optional[List[str]] = None,
    meterpreter_info: Optional[Dict[str, Any]] = None,
    full: bool = False,
) -> None:
    """Print a beautifully formatted kill summary."""
    status_style = THEME["confirmed"] if confirmed else THEME["lost"]
    status_text = "CONFIRMED" if confirmed else "LOST"

    content_parts = []

    # Status and target
    content_parts.append(Text.from_markup(
        f"[bold]Status:[/bold] [{status_style}]{status_text}[/{status_style}]\n"
        f"[bold]Target:[/bold] {host}:{port}"
    ))

    # Attack vector
    if via_exploit or via_payload:
        vector_text = "\n\n[bold]Attack Vector:[/bold]"
        if via_exploit:
            vector_text += f"\n  Exploit: [cyan]{via_exploit}[/cyan]"
        if via_payload:
            vector_text += f"\n  Payload: [yellow]{via_payload}[/yellow]"
        content_parts.append(Text.from_markup(vector_text))

    # Vulnerabilities
    if vulns:
        vuln_limit = None if full else 5
        vulns_to_show = vulns[:vuln_limit]
        vuln_text = "\n\n[bold]Known Vulnerabilities:[/bold]"
        for vuln in vulns_to_show:
            vuln_text += f"\n  [red]• {vuln}[/red]"
        if not full and len(vulns) > 5:
            vuln_text += f"\n  [dim]... and {len(vulns) - 5} more[/dim]"
        content_parts.append(Text.from_markup(vuln_text))

    # Meterpreter info
    if meterpreter_info:
        meter_text = "\n\n[bold]Meterpreter Info:[/bold]"
        if meterpreter_info.get("user"):
            meter_text += f"\n  User: [green]{meterpreter_info['user']}[/green]"
        if meterpreter_info.get("computer"):
            meter_text += f"\n  Computer: {meterpreter_info['computer']}"
        if meterpreter_info.get("os"):
            meter_text += f"\n  OS: {meterpreter_info['os']}"
        content_parts.append(Text.from_markup(meter_text))

    from rich.console import Group
    content = Group(*content_parts)

    console.print(Panel(
        content,
        title=f"[bold]Kill #{kill_id}[/bold]",
        subtitle=f"[{status_style}]{kill_type.upper()}[/{status_style}]",
        border_style="green" if confirmed else "red",
        expand=True,
        padding=(1, 2),
    ))


# =============================================================================
# Contract Printing
# =============================================================================


def print_contract(
    weapon_name: str,
    target_host: str,
    bullet_name: str,
    ready: bool,
    profiled: bool,
    profile_result: Optional[bool] = None,
    executed: bool = False,
    kill_id: Optional[int] = None,
    full: bool = False,
) -> None:
    """Print a beautifully formatted contract summary."""
    _ = full  # Reserved

    # Determine status
    if executed and kill_id:
        status = "EXECUTED - KILL CONFIRMED"
        status_style = THEME["success"]
        border_style = "green"
    elif executed:
        status = "EXECUTED - FAILED"
        status_style = THEME["error"]
        border_style = "red"
    elif profiled and profile_result:
        status = "PROFILED - VULNERABLE"
        status_style = THEME["warning"]
        border_style = "yellow"
    elif profiled:
        status = "PROFILED - NOT VULNERABLE"
        status_style = THEME["dim"]
        border_style = "dim"
    elif ready:
        status = "READY"
        status_style = THEME["info"]
        border_style = "blue"
    else:
        status = "NOT READY"
        status_style = THEME["dim"]
        border_style = "dim"

    content_parts = []
    content_parts.append(Text.from_markup(
        f"[bold]Status:[/bold] [{status_style}]{status}[/{status_style}]\n\n"
        f"[bold]Target:[/bold] {target_host}\n"
        f"[bold]Weapon:[/bold] [cyan]{weapon_name}[/cyan]\n"
        f"[bold]Bullet:[/bold] [yellow]{bullet_name}[/yellow]"
    ))

    if kill_id:
        content_parts.append(Text.from_markup(f"\n\n[bold green]Kill ID: #{kill_id}[/bold green]"))

    from rich.console import Group
    content = Group(*content_parts)

    console.print(Panel(
        content,
        title="[bold]Contract[/bold]",
        subtitle=f"[{status_style}]{status}[/{status_style}]",
        border_style=border_style,
        expand=True,
        padding=(1, 2),
    ))


# =============================================================================
# Mass Contract Printing
# =============================================================================


def print_mass_contract(
    weapon_name: str,
    targets: List[str],
    bullet_name: Optional[str],
    kills: List[tuple],  # List of (host, port) tuples
    failures: List[tuple],  # List of (host, error) tuples
    attempted: int,
    full: bool = False,
) -> None:
    """Print a beautifully formatted mass contract summary."""
    success_rate = len(kills) / attempted if attempted > 0 else 0

    # Determine overall status
    if attempted == 0:
        status = "NOT EXECUTED"
        border_style = "dim"
    elif success_rate >= 0.8:
        status = f"SUCCESS ({success_rate:.0%})"
        border_style = "green"
    elif success_rate >= 0.5:
        status = f"PARTIAL ({success_rate:.0%})"
        border_style = "yellow"
    else:
        status = f"FAILED ({success_rate:.0%})"
        border_style = "red"

    # Stats table
    stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    stats_table.add_column("Metric", style="bold")
    stats_table.add_column("Value", justify="right")
    stats_table.add_row("Targets", str(len(targets)))
    stats_table.add_row("Attempted", str(attempted))
    stats_table.add_row("Kills", f"[green]{len(kills)}[/green]")
    stats_table.add_row("Failures", f"[red]{len(failures)}[/red]")
    stats_table.add_row("Success Rate", f"[bold]{success_rate:.1%}[/bold]")

    content_parts = [stats_table]

    # Kills list
    if kills:
        kill_limit = None if full else 5
        kills_to_show = kills[:kill_limit]
        kill_text = "\n[bold green]Confirmed Kills:[/bold green]"
        for host, port in kills_to_show:
            kill_text += f"\n  [green]✓[/green] {host}:{port}"
        if not full and len(kills) > 5:
            kill_text += f"\n  [dim]... and {len(kills) - 5} more[/dim]"
        content_parts.append(Text.from_markup(kill_text))

    # Failures list
    if failures:
        fail_limit = None if full else 5
        fails_to_show = failures[:fail_limit]
        fail_text = "\n[bold red]Failures:[/bold red]"
        for host, error in fails_to_show:
            fail_text += f"\n  [red]✗[/red] {host}: {error}"
        if not full and len(failures) > 5:
            fail_text += f"\n  [dim]... and {len(failures) - 5} more[/dim]"
        content_parts.append(Text.from_markup(fail_text))

    from rich.console import Group
    content = Group(*content_parts)

    subtitle_parts = [status]
    if bullet_name:
        subtitle_parts.append(f"bullet={bullet_name}")

    console.print(Panel(
        content,
        title=f"[bold]MassContract: {weapon_name}[/bold]",
        subtitle=" | ".join(subtitle_parts),
        border_style=border_style,
        expand=True,
        padding=(1, 2),
    ))


# =============================================================================
# Catalog Printing
# =============================================================================


def print_weapon_info(
    fullname: str,
    name: str,
    weapon_type: str,
    rank: str,
    service: Optional[str] = None,
    port: Optional[int] = None,
    platforms: Optional[List[str]] = None,
    cves: Optional[List[str]] = None,
    description: Optional[str] = None,
    authors: Optional[List[str]] = None,
    full: bool = False,
) -> None:
    """Print a beautifully formatted WeaponInfo summary."""
    rank_style = get_rank_style(rank)

    # Build subtitle
    subtitle_parts = [f"[{rank_style}]{rank.upper()}[/{rank_style}]"]
    if service:
        subtitle_parts.append(f"service={service}")
    if port:
        subtitle_parts.append(f"port={port}")

    content_parts = []

    # Basic info
    info_text = f"[bold]Type:[/bold] {weapon_type.upper()}\n"
    if platforms:
        info_text += f"[bold]Platforms:[/bold] {', '.join(platforms)}\n"
    if cves:
        info_text += f"[bold]CVEs:[/bold] [red]{', '.join(cves)}[/red]\n"
    content_parts.append(Text.from_markup(info_text))

    # Description
    if description:
        content_parts.append(Text(f"\n{description}", style="white"))

    # Authors
    if authors:
        auth_limit = None if full else 3
        auths_to_show = authors[:auth_limit]
        auth_text = f"\n\n[bold]Authors:[/bold] {', '.join(auths_to_show)}"
        if not full and len(authors) > 3:
            auth_text += f" [dim](+{len(authors) - 3} more)[/dim]"
        content_parts.append(Text.from_markup(auth_text))

    from rich.console import Group
    content = Group(*content_parts)

    console.print(Panel(
        content,
        title=f"[bold]{fullname}[/bold]",
        subtitle=" | ".join(subtitle_parts),
        border_style="cyan",
        expand=True,
        padding=(1, 2),
    ))


def print_bullet_info(
    name: str,
    platform: str,
    arch: str,
    bullet_type: str,
    connection: str,
    is_meterpreter: bool,
    is_shell: bool,
    handler: str,
    full: bool = False,
) -> None:
    """Print a beautifully formatted BulletInfo summary."""
    _ = full  # Reserved

    payload_type = "Meterpreter" if is_meterpreter else "Shell" if is_shell else "Other"
    type_style = "magenta" if is_meterpreter else "yellow" if is_shell else "white"

    content = Text.from_markup(
        f"[bold]Platform:[/bold] {platform}    [bold]Arch:[/bold] {arch}\n"
        f"[bold]Type:[/bold] {bullet_type}    [bold]Connection:[/bold] {connection}\n"
        f"[bold]Payload:[/bold] [{type_style}]{payload_type}[/{type_style}]\n"
        f"[bold]Handler:[/bold] {handler}"
    )

    console.print(Panel(
        content,
        title=f"[bold]{name}[/bold]",
        subtitle=f"[{type_style}]{payload_type}[/{type_style}] | {bullet_type} | {connection}",
        border_style="magenta",
        expand=True,
        padding=(1, 2),
    ))


# =============================================================================
# Utility Functions (for CLI/demo)
# =============================================================================


def icon(ok: bool) -> str:
    """Return themed checkmark or X icon."""
    return "[green]✓[/green]" if ok else "[red]✗[/red]"


def warn_icon() -> str:
    """Return themed warning icon."""
    return "[yellow]○[/yellow]"


def print_section(title: str, subtitle: str = "") -> None:
    """Print a section header with optional subtitle."""
    from rich.rule import Rule
    console.print()
    console.print(Rule(f"[bold]{title}[/bold]", style="cyan"))
    if subtitle:
        console.print(f"  [dim]{subtitle}[/dim]")
    console.print()


def print_status(message: str, status: str = "info") -> None:
    """Print a status message with themed icon.

    Args:
        message: The message to print
        status: One of "success", "error", "warning", "info"
    """
    icons = {
        "success": "[green]✓[/green]",
        "error": "[red]✗[/red]",
        "warning": "[yellow]○[/yellow]",
        "info": "[cyan]→[/cyan]",
    }
    console.print(f"  {icons.get(status, icons['info'])} {message}")


def print_kv(label: str, value: str, style: str = "cyan") -> None:
    """Print a single key-value pair."""
    console.print(f"  [dim]•[/dim] {label}: [{style}]{value}[/{style}]")


def print_list(items: list, title: str = "") -> None:
    """Print a bulleted list of (label, value) tuples or plain strings.

    Args:
        items: List of (label, value) tuples or plain strings
        title: Optional title to print above the list
    """
    if title:
        console.print(f"[bold]{title}[/bold]")
    for item in items:
        if isinstance(item, tuple) and len(item) >= 2:
            label, value = item[0], item[1]
            console.print(f"  [dim]•[/dim] {label}: [cyan]{value}[/cyan]")
        else:
            console.print(f"  [dim]•[/dim] {item}")


def print_banner() -> None:
    """Print the Assassinate ASCII banner."""
    banner = """[bold cyan]
    █████╗ ███████╗███████╗ █████╗ ███████╗███████╗██╗███╗   ██╗ █████╗ ████████╗███████╗
   ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██║████╗  ██║██╔══██╗╚══██╔══╝██╔════╝
   ███████║███████╗███████╗███████║███████╗███████╗██║██╔██╗ ██║███████║   ██║   █████╗
   ██╔══██║╚════██║╚════██║██╔══██║╚════██║╚════██║██║██║╚██╗██║██╔══██║   ██║   ██╔══╝
   ██║  ██║███████║███████║██║  ██║███████║███████║██║██║ ╚████║██║  ██║   ██║   ███████╗
   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
[/bold cyan]"""
    console.print(banner)
    console.print("[bold]  Precision Exploitation Framework[/bold]\n")


# =============================================================================
# Re-exports for convenience
# =============================================================================

__all__ = [
    # Global console and theme
    "console", "THEME", "get_rank_style",
    # Printing functions
    "print_module", "print_session", "print_kill",
    "print_contract", "print_mass_contract",
    "print_weapon_info", "print_bullet_info",
    # Utility functions (for CLI/demo)
    "icon", "warn_icon", "print_section", "print_status", "print_kv", "print_list", "print_banner",
    # Rich re-exports
    "Panel", "Table", "Text", "box",
]
