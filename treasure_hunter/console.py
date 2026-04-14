"""
CAPTAIN'S DECK -- Interactive console for treasure-hunter

Pirate-themed terminal UI for step-by-step engagement control.
Navigate with arrow keys, Enter to select, q to go back.

Run with: treasure-hunter (no args) or treasure-hunter --interactive
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from pathlib import Path

from .models import Finding, ScanResult, Severity
from .scanner import ScanContext, TreasureScanner
from .tui import (
    BOLD, RESET, THEME,
    bold, clear, color, dim_text, enter_fullscreen, exit_fullscreen,
    fg, getch, gradient, gradient_multi, init_terminal,
    menu_select, panel, progress_bar, prompt, render_banner,
    severity_badge, Spinner, strip_ansi, table, visible_len,
    get_terminal_size, HIDE_CURSOR, SHOW_CURSOR,
)


class CaptainsDeck:
    """Interactive console for treasure-hunter engagements."""

    def __init__(self) -> None:
        self.scan_result: ScanResult | None = None
        self.credentials: list = []
        self.audit_result = None
        self.lateral_result = None

    def run(self) -> int:
        """Main entry point for interactive mode."""
        init_terminal()
        try:
            while True:
                choice = self._main_menu()
                if choice == 0:
                    self._scout_waters()
                elif choice == 1:
                    self._open_chest()
                elif choice == 2:
                    self._count_gold()
                elif choice == 3:
                    self._board_ship()
                elif choice == 4:
                    self._bury_treasure()
                elif choice == 5:
                    return 0
                elif choice == -1:
                    return 0
        except KeyboardInterrupt:
            return 0

    def _main_menu(self) -> int:
        clear()
        print(render_banner())
        print()

        # Status line
        if self.scan_result:
            r = self.scan_result
            findings = len(r.findings)
            creds = r.total_credentials_harvested
            status = (
                f'  {color(chr(9679), THEME.success)} Scan complete: '
                f'{bold(str(findings), THEME.accent)} findings, '
                f'{bold(str(creds), THEME.accent)} credentials'
            )
            if self.lateral_result:
                lc = self.lateral_result.targets_compromised
                status += f', {bold(str(lc), THEME.primary)} hosts compromised'
            print(status)
        else:
            print(f'  {color(chr(9679), THEME.dim)} No scan loaded')

        print()

        options = [
            'Scout the Waters     (scan target)',
            'Open the Chest       (browse findings)',
            'Count the Gold       (view credentials)',
            'Board Their Ship     (lateral movement)',
            'Bury the Treasure    (export / encrypt)',
            'Abandon Ship         (exit)',
        ]

        choice = menu_select(options, title='')
        return choice

    # ================================================================
    # [1] Scout the Waters -- Scan
    # ================================================================

    def _scout_waters(self) -> None:
        clear()
        print(f'\n  {gradient("Scout the Waters", (255, 50, 50), (255, 200, 0))}')
        print(f'  {dim_text("Select scan profile and targets")}\n')

        profiles = ['smash    (5 min, fast grab)', 'triage   (30 min, balanced)',
                     'full     (no limit, everything)', 'stealth  (low profile)']
        profile_names = ['smash', 'triage', 'full', 'stealth']

        idx = menu_select(profiles, title='Scan Profile')
        if idx == -1:
            return

        profile_name = profile_names[idx]

        print()
        target_input = prompt('  Target path (Enter for default): ')
        targets = None
        if target_input.strip():
            targets = [t.strip() for t in target_input.split(',')]

        print()
        with Spinner(f'Scanning with {profile_name} profile...', spin_color=THEME.primary):
            from .cli import SCAN_PROFILES, get_default_targets, filter_existing_paths
            profile = SCAN_PROFILES[profile_name]
            config = profile.config.copy()

            if targets:
                target_paths = filter_existing_paths(targets)
            else:
                target_paths = filter_existing_paths(get_default_targets())

            if not target_paths:
                print(f'\n  {color("No accessible targets found", THEME.critical)}')
                print(f'  {dim_text("[Enter] continue  [b] back")}')
                getch()
                return

            config['show_progress'] = False
            context = ScanContext(target_paths, **config)
            scanner = TreasureScanner(context)
            self.scan_result = scanner.scan()

        # Extract credentials and audit from the scanner internals
        if hasattr(scanner, '_grabber_context') and scanner._grabber_context:
            self.credentials = scanner._grabber_context.all_credentials
        if hasattr(scanner, '_credential_audit'):
            self.audit_result = scanner._credential_audit
        if hasattr(scanner, '_lateral_result'):
            self.lateral_result = scanner._lateral_result

        # Show summary
        self._show_scan_summary()

    def _show_scan_summary(self) -> None:
        if not self.scan_result:
            return

        r = self.scan_result
        print()

        sev_counts = {
            'critical': len([f for f in r.findings if f.severity == Severity.CRITICAL]),
            'high': len([f for f in r.findings if f.severity == Severity.HIGH]),
            'medium': len([f for f in r.findings if f.severity == Severity.MEDIUM]),
            'low': len([f for f in r.findings if f.severity == Severity.LOW]),
        }

        summary_lines = [
            f'{bold("Scan Complete", THEME.success)}',
            '',
            f'Files scanned:  {bold(f"{r.total_files_scanned:,}", THEME.fg)}',
            f'Duration:       {bold(f"{(r.completed_at - r.started_at).total_seconds():.1f}s", THEME.fg)}',
            '',
            f'{severity_badge("critical")} CRITICAL: {bold(str(sev_counts["critical"]), THEME.critical)}',
            f'{severity_badge("high")}     HIGH:     {bold(str(sev_counts["high"]), THEME.high)}',
            f'{severity_badge("medium")}   MEDIUM:   {bold(str(sev_counts["medium"]), THEME.medium)}',
            f'{severity_badge("low")}      LOW:      {bold(str(sev_counts["low"]), THEME.low)}',
            '',
            f'Credentials:    {bold(str(r.total_credentials_harvested), THEME.accent)}',
        ]

        print(panel(summary_lines, title='Voyage Report', width=50))
        print(f'\n  {dim_text("[Enter] continue  [b] back")}')
        getch()

    # ================================================================
    # [2] Open the Chest -- Browse Findings
    # ================================================================

    def _open_chest(self) -> None:
        if not self.scan_result or not self.scan_result.findings:
            clear()
            print(f'\n  {color("No findings to browse. Run a scan first.", THEME.dim)}')
            print(f'  {dim_text("[Enter] continue  [b] back")}')
            getch()
            return

        findings = sorted(self.scan_result.findings, key=lambda f: f.total_score, reverse=True)
        page = 0
        page_size = max(get_terminal_size()[1] - 10, 5)
        filter_sev = None  # None = all

        while True:
            clear()
            print(f'\n  {gradient("Open the Chest", (255, 200, 0), (255, 120, 0))}')

            # Apply filter
            if filter_sev:
                display = [f for f in findings if f.severity.name.lower() == filter_sev]
            else:
                display = findings

            total_pages = max(1, (len(display) + page_size - 1) // page_size)
            page = min(page, total_pages - 1)
            start = page * page_size
            end = min(start + page_size, len(display))
            page_items = display[start:end]

            filter_str = f' [{filter_sev.upper()}]' if filter_sev else ' [ALL]'
            print(f'  {dim_text(f"Page {page + 1}/{total_pages} -- {len(display)} findings{filter_str}")}\n')

            # Build table rows
            headers = ['Sev', 'Score', 'Path', 'Type']
            rows = []
            for f in page_items:
                badge = severity_badge(f.severity.name.lower())
                path = f.file_path
                if len(path) > 40:
                    path = '...' + path[-37:]
                sig_types = ', '.join(set(s.category.value for s in f.signals[:3]))
                rows.append([badge, str(f.total_score), path, sig_types or '-'])

            if rows:
                print(table(headers, rows))
            else:
                print(f'  {dim_text("No findings match filter")}')

            print(f'\n  {dim_text("[n]ext [p]rev [c]ritical [h]igh [m]edium [a]ll [b/q]back")}')

            key = getch()
            if key in ('q', 'b', 'esc', '\x1b'):
                break
            elif key == 'n' and page < total_pages - 1:
                page += 1
            elif key == 'p' and page > 0:
                page -= 1
            elif key == 'c':
                filter_sev = 'critical'
                page = 0
            elif key == 'h':
                filter_sev = 'high'
                page = 0
            elif key == 'm':
                filter_sev = 'medium'
                page = 0
            elif key == 'a':
                filter_sev = None
                page = 0

    # ================================================================
    # [3] Count the Gold -- Credentials
    # ================================================================

    def _count_gold(self) -> None:
        if not self.credentials:
            clear()
            print(f'\n  {color("No credentials extracted. Run a scan first.", THEME.dim)}')
            print(f'  {dim_text("[Enter] continue  [b] back")}')
            getch()
            return

        while True:
            clear()
            print(f'\n  {gradient("Count the Gold", (255, 200, 0), (255, 150, 0))}')

            # Audit summary
            if self.audit_result:
                ca = self.audit_result
                audit_lines = [
                    f'Passwords:  {bold(str(ca.total_passwords), THEME.accent)}  '
                    f'({bold(str(ca.unique_passwords), THEME.fg)} unique)',
                ]
                if ca.reused_passwords:
                    audit_lines.append(
                        f'{color("[!]", THEME.high)} Reused: {bold(str(len(ca.reused_passwords)), THEME.high)} password(s) on multiple services'
                    )
                if ca.common_passwords:
                    audit_lines.append(
                        f'{color("[!!]", THEME.critical)} Common/default: {bold(str(len(ca.common_passwords)), THEME.critical)} account(s)'
                    )
                if ca.high_value_accounts:
                    audit_lines.append(
                        f'{color("[!!]", THEME.critical)} Admin/service: {bold(str(len(ca.high_value_accounts)), THEME.primary)} high-value account(s)'
                    )
                if ca.strength_distribution:
                    d = ca.strength_distribution
                    audit_lines.append(
                        f'Strength: {color(str(d.get("strong", 0)), THEME.success)} strong, '
                        f'{color(str(d.get("good", 0)), THEME.info)} good, '
                        f'{color(str(d.get("fair", 0)), THEME.medium)} fair, '
                        f'{color(str(d.get("weak", 0)), THEME.critical)} weak'
                    )
                print()
                print(panel(audit_lines, title='Credential Audit', width=60))

            # Credentials table
            print()
            headers = ['Source', 'Type', 'App', 'User', 'Value']
            rows = []
            for cred in self.credentials[:50]:
                val = cred.decrypted_value
                if val and len(val) > 20:
                    val = val[:17] + '...'
                elif not val and cred.encrypted_value:
                    val = dim_text('[encrypted]')
                elif not val:
                    val = dim_text('-')

                ctype = cred.credential_type
                if ctype == 'password':
                    ctype = color(ctype, THEME.primary)
                elif ctype == 'token':
                    ctype = color(ctype, THEME.info)
                elif ctype == 'credit_card':
                    ctype = color(ctype, THEME.accent)

                rows.append([
                    cred.source_module,
                    ctype,
                    cred.target_application,
                    cred.username or '-',
                    val,
                ])

            if rows:
                print(table(headers, rows))
                if len(self.credentials) > 50:
                    print(f'  {dim_text(f"... and {len(self.credentials) - 50} more")}')

            print(f'\n  {dim_text("[b/q] back")}')
            key = getch()
            if key in ('q', 'b', 'esc', '\x1b'):
                break

    # ================================================================
    # [4] Board Their Ship -- Lateral Movement
    # ================================================================

    def _board_ship(self) -> None:
        if not self.scan_result:
            clear()
            print(f'\n  {color("Run a scan first to extract credentials.", THEME.dim)}')
            print(f'  {dim_text("[Enter] continue  [b] back")}')
            getch()
            return

        clear()
        print(f'\n  {gradient("Board Their Ship", (255, 50, 50), (255, 120, 0))}')
        print(f'  {dim_text("Test extracted credentials against network hosts")}\n')

        if not self.credentials:
            print(f'  {color("No credentials available for lateral movement.", THEME.dim)}')
            print(f'  {dim_text("[Enter] continue  [b] back")}')
            getch()
            return

        # Count usable password creds
        usable = [c for c in self.credentials
                  if c.credential_type == 'password' and c.username and c.decrypted_value]
        print(f'  Usable credentials: {bold(str(len(usable)), THEME.accent)}')
        print()

        target_input = prompt('  Target (auto, IP, CIDR, or hostname): ') or 'auto'
        max_hosts_input = prompt('  Max hosts [10]: ') or '10'

        print()

        try:
            max_hosts = int(max_hosts_input)
        except ValueError:
            max_hosts = 10

        from .lateral import LateralConfig, LateralScanner

        config = LateralConfig(
            enabled=True,
            target_spec=target_input,
            max_hosts=max_hosts,
            attempt_delay=0.5,
        )

        with Spinner('Probing network hosts...', spin_color=THEME.primary):
            lat_scanner = LateralScanner(
                config=config,
                credentials=self.credentials,
            )
            self.lateral_result = lat_scanner.run()

        lr = self.lateral_result
        print()

        result_lines = [
            f'Hosts discovered:  {bold(str(lr.targets_discovered), THEME.fg)}',
            f'Hosts compromised: {bold(str(lr.targets_compromised), THEME.success if lr.targets_compromised else THEME.dim)}',
            f'Creds tested:      {bold(str(lr.credentials_tested), THEME.fg)}',
            f'Auth successes:    {bold(str(lr.auth_successes), THEME.success if lr.auth_successes else THEME.dim)}',
        ]
        if lr.lockout_skips:
            result_lines.append(f'Lockout skips:     {bold(str(lr.lockout_skips), THEME.medium)}')

        for t in lr.targets:
            if t.compromised:
                result_lines.append(f'{color("[+]", THEME.success)} {bold(t.host, THEME.success)} -- access granted')
            elif t.auth_results:
                result_lines.append(f'{color("[-]", THEME.dim)} {t.host} -- {len(t.auth_results)} attempts, no access')

        print(panel(result_lines, title='Lateral Movement', width=55))
        print(f'\n  {dim_text("[Enter] continue  [b] back")}')
        getch()

    # ================================================================
    # [5] Bury the Treasure -- Export
    # ================================================================

    def _bury_treasure(self) -> None:
        if not self.scan_result:
            clear()
            print(f'\n  {color("No scan results to export. Run a scan first.", THEME.dim)}')
            print(f'  {dim_text("[Enter] continue  [b] back")}')
            getch()
            return

        clear()
        print(f'\n  {gradient("Bury the Treasure", (255, 200, 0), (255, 120, 0))}')
        print(f'  {dim_text("Export and protect your loot")}\n')

        options = [
            'Save JSONL results',
            'Save encrypted JSONL',
            'Generate HTML report',
            'Save all (JSONL + encrypted + HTML)',
            'Back',
        ]

        choice = menu_select(options)
        if choice in (-1, 4):
            return

        print()
        output_dir = prompt('  Output directory [.]: ') or '.'
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)

        from .cli import save_results

        if choice in (0, 3):
            jsonl_path = os.path.join(output_dir, 'loot.jsonl')
            save_results(self.scan_result, jsonl_path)
            print(f'  {color("[+]", THEME.success)} JSONL: {jsonl_path}')

        if choice in (1, 3):
            jsonl_path = os.path.join(output_dir, 'loot.jsonl')
            if choice == 1:
                save_results(self.scan_result, jsonl_path)
            passphrase = prompt('  Encryption passphrase: ')
            if passphrase:
                from .crypto import encrypt_and_shred
                enc_path = encrypt_and_shred(jsonl_path, passphrase)
                print(f'  {color("[+]", THEME.success)} Encrypted: {enc_path}')

        if choice in (2, 3):
            html_path = os.path.join(output_dir, 'report.html')
            from .report import generate_html_report
            generate_html_report(self.scan_result, html_path)
            print(f'  {color("[+]", THEME.success)} HTML report: {html_path}')

        print(f'\n  {dim_text("[Enter] continue  [b] back")}')
        getch()


def run_interactive() -> int:
    """Entry point for interactive mode."""
    deck = CaptainsDeck()
    return deck.run()
