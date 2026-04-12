"""
CLI INTERFACE — Command-line entry point for treasure-hunter

Provides four scan profiles optimized for different engagement types:

SMASH (5 min):   Quick hit - credentials & recent files only
TRIAGE (30 min): Balanced scan - high-value targets with some depth
FULL (2+ hours): Comprehensive scan - everything with content analysis
STEALTH (8+ hours): Low-profile scan - minimal system impact

Each profile tunes threading, time limits, and scope to match operational needs.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import sys
import traceback
from pathlib import Path

from .models import ScanResult
from .scanner import ScanContext, TreasureScanner


class ScanProfile:
    """Pre-configured scan settings for different engagement types."""

    def __init__(self, name: str, description: str, **kwargs):
        self.name = name
        self.description = description
        self.config = kwargs


# Pre-defined scan profiles optimized for different scenarios
SCAN_PROFILES = {
    'smash': ScanProfile(
        'smash',
        'Quick 5-minute smash-and-grab for immediate value',
        max_threads=16,
        time_limit=300,  # 5 minutes
        min_score_threshold=50,  # Only high-confidence hits
        max_file_size=10 * 1024 * 1024,  # 10MB limit
        content_sample_size=4096,  # 4KB samples
        target_extensions={
            '.kdbx', '.pem', '.key', '.env', '.pfx', '.rdp', '.ovpn',
            '.pst', '.sqlite', '.db', '.sql', '.bak'
        }
    ),

    'triage': ScanProfile(
        'triage',
        'Balanced 30-minute scan for operational planning',
        max_threads=12,
        time_limit=1800,  # 30 minutes
        min_score_threshold=35,
        max_file_size=50 * 1024 * 1024,  # 50MB limit
        content_sample_size=8192,  # 8KB samples
    ),

    'full': ScanProfile(
        'full',
        'Comprehensive 2+ hour scan for complete intelligence gathering',
        max_threads=8,
        time_limit=None,  # No time limit
        min_score_threshold=25,
        max_file_size=100 * 1024 * 1024,  # 100MB limit
        content_sample_size=16384,  # 16KB samples
    ),

    'stealth': ScanProfile(
        'stealth',
        'Low-profile 8+ hour scan with minimal system impact',
        max_threads=2,
        time_limit=None,  # No time limit
        min_score_threshold=20,
        max_file_size=200 * 1024 * 1024,  # 200MB limit
        content_sample_size=32768,  # 32KB samples
    )
}


def setup_logging(verbosity: int = 1) -> None:
    """Configure logging based on verbosity level."""
    levels = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(verbosity, len(levels) - 1)]

    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )

    # Reduce noise from external libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)


def get_default_targets() -> list[str]:
    """Get platform-appropriate default scan targets."""
    if platform.system() == 'Windows':
        user_profile = os.environ.get('USERPROFILE', r'C:\Users\Default')
        targets = [
            f"{user_profile}\\Documents",
            f"{user_profile}\\Desktop",
            f"{user_profile}\\Downloads",
            f"{user_profile}\\AppData\\Roaming",
            f"{user_profile}\\AppData\\Local",
            "C:\\Temp",
            "C:\\Windows\\Temp",
        ]
        # Auto-detect mapped network drives
        targets.extend(_enumerate_network_drives())
        return targets
    else:
        home = os.path.expanduser('~')
        return [
            f"{home}/Documents",
            f"{home}/Desktop",
            f"{home}/Downloads",
            f"{home}/.ssh",
            f"{home}/.aws",
            f"{home}/.config",
            "/tmp",
            "/var/tmp"
        ]


def _enumerate_network_drives() -> list[str]:
    """Detect mapped network drives on Windows (D:-Z:)."""
    if platform.system() != 'Windows':
        return []

    drives = []
    for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
        drive_path = f"{letter}:\\"
        if os.path.exists(drive_path):
            try:
                # Check if it's a network drive via GetDriveType
                import ctypes
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                if drive_type == 4:  # DRIVE_REMOTE
                    drives.append(drive_path)
            except (AttributeError, OSError):
                continue
    return drives


def filter_existing_paths(paths: list[str]) -> list[str]:
    """Filter to only include paths that exist and are accessible."""
    existing = []
    for path in paths:
        try:
            path_obj = Path(path)
            if path_obj.exists() and path_obj.is_dir():
                existing.append(path)
        except (PermissionError, OSError):
            continue
    return existing


def save_results(results: ScanResult, output_path: str) -> None:
    """Save scan results to JSONL format for streaming compatibility."""
    output_file = Path(output_path)

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write results as JSONL (one JSON object per line)
    with open(output_file, 'w', encoding='utf-8') as f:
        # Metadata header
        header = {
            'type': 'scan_metadata',
            'scan_id': results.scan_id,
            'started_at': results.started_at.isoformat(),
            'completed_at': results.completed_at.isoformat() if results.completed_at else None,
            'target_paths': results.target_paths,
            'stats': {
                'total_files_scanned': results.total_files_scanned,
                'total_dirs_scanned': results.total_dirs_scanned,
                'total_findings': len(results.findings),
                'critical': len([f for f in results.findings if f.severity.value >= 5]),
                'high': len([f for f in results.findings if f.severity.value >= 4]),
                'medium': len([f for f in results.findings if f.severity.value >= 3]),
                'low': len([f for f in results.findings if f.severity.value >= 2]),
            }
        }
        f.write(json.dumps(header) + '\n')

        # Individual findings
        for finding in sorted(results.findings, key=lambda x: x.total_score, reverse=True):
            finding_data = {
                'type': 'finding',
                **finding.to_dict()
            }
            f.write(json.dumps(finding_data) + '\n')

        # Errors (if any)
        if results.errors:
            error_data = {
                'type': 'errors',
                'errors': results.errors
            }
            f.write(json.dumps(error_data) + '\n')


def print_summary(results: ScanResult) -> None:
    """Print a human-readable summary of scan results."""
    print("\n" + "="*60)
    print(f"TREASURE-HUNTER SCAN COMPLETE")
    print("="*60)

    print(f"Scan ID: {results.scan_id}")
    print(f"Duration: {(results.completed_at - results.started_at).total_seconds():.1f}s")
    print(f"Files scanned: {results.total_files_scanned:,}")
    print(f"Directories scanned: {results.total_dirs_scanned:,}")

    print(f"\n📊 FINDINGS BREAKDOWN:")
    critical = [f for f in results.findings if f.severity.value >= 5]
    high = [f for f in results.findings if f.severity.value >= 4]
    medium = [f for f in results.findings if f.severity.value >= 3]
    low = [f for f in results.findings if f.severity.value >= 2]

    print(f"  🚨 CRITICAL: {len(critical):,}")
    print(f"  🔴 HIGH:     {len(high):,}")
    print(f"  🟡 MEDIUM:   {len(medium):,}")
    print(f"  🟢 LOW:      {len(low):,}")
    print(f"  📈 TOTAL:    {len(results.findings):,}")

    # Show top findings
    if results.findings:
        print(f"\n🏆 TOP FINDINGS:")
        top_findings = sorted(results.findings, key=lambda x: x.total_score, reverse=True)[:5]

        for i, finding in enumerate(top_findings, 1):
            severity_emoji = {
                5: "🚨", 4: "🔴", 3: "🟡", 2: "🟢", 1: "ℹ️"
            }.get(finding.severity.value, "❓")

            path_display = finding.file_path
            if len(path_display) > 50:
                path_display = "..." + path_display[-47:]

            print(f"  {i}. {severity_emoji} {path_display}")
            print(f"     Score: {finding.total_score} | Signals: {len(finding.signals)}")

    if results.errors:
        print(f"\n⚠️  {len(results.errors)} errors encountered during scan")


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description='treasure-hunter: Red team file discovery and analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCAN PROFILES:
  smash     Quick 5-minute smash-and-grab (default)
  triage    Balanced 30-minute operational scan
  full      Comprehensive 2+ hour intelligence gathering
  stealth   Low-profile 8+ hour minimal-impact scan

EXAMPLES:
  treasure-hunter                    # Quick smash scan of default locations
  treasure-hunter -p full           # Full comprehensive scan
  treasure-hunter -t C:\\Users       # Target specific directory
  treasure-hunter -o results.jsonl  # Save results to file
  treasure-hunter -vv               # Verbose logging

OPERATIONAL SECURITY:
  - Minimal disk writes (JSONL output only)
  - No external network connections
  - Graceful error handling to avoid crashes
  - Thread limits to prevent resource exhaustion
        """
    )

    parser.add_argument(
        '-p', '--profile',
        choices=list(SCAN_PROFILES.keys()),
        default='smash',
        help='Scan profile to use (default: smash)'
    )

    parser.add_argument(
        '-t', '--targets',
        nargs='+',
        help='Target directories to scan (default: platform-appropriate locations)'
    )

    parser.add_argument(
        '-o', '--output',
        default='treasure-hunter-results.jsonl',
        help='Output file for results (default: treasure-hunter-results.jsonl)'
    )

    parser.add_argument(
        '--time-limit',
        type=int,
        help='Override profile time limit (seconds)'
    )

    parser.add_argument(
        '--threads',
        type=int,
        help='Override profile thread count'
    )

    parser.add_argument(
        '--min-score',
        type=int,
        help='Minimum score threshold for findings'
    )

    parser.add_argument(
        '--no-grabbers',
        action='store_true',
        help='Disable all grabber modules (scan-only mode)'
    )

    parser.add_argument(
        '--grabbers',
        nargs='*',
        default=None,
        metavar='MODULE',
        help='Enable specific grabber modules (default: all applicable)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=1,
        help='Increase verbosity (-v, -vv, -vvv)'
    )

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress all output except errors'
    )

    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='List available scan profiles and exit'
    )

    return parser


def main() -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle special modes
    if args.list_profiles:
        print("Available scan profiles:")
        print()
        for name, profile in SCAN_PROFILES.items():
            print(f"  {name:8} - {profile.description}")
        return 0

    # Setup logging
    if args.quiet:
        setup_logging(0)
    else:
        setup_logging(args.verbose)

    logger = logging.getLogger(__name__)

    try:
        # Get scan profile
        profile = SCAN_PROFILES[args.profile]
        logger.info(f"Using scan profile: {profile.name}")

        # Determine target paths
        if args.targets:
            target_paths = filter_existing_paths(args.targets)
        else:
            target_paths = filter_existing_paths(get_default_targets())

        if not target_paths:
            print("❌ No accessible target directories found")
            return 1

        logger.info(f"Scanning {len(target_paths)} target paths")

        # Create scan context with profile settings
        context_kwargs = profile.config.copy()

        # Apply CLI overrides
        if args.time_limit is not None:
            context_kwargs['time_limit'] = args.time_limit
        if args.threads is not None:
            context_kwargs['max_threads'] = args.threads
        if args.min_score is not None:
            context_kwargs['min_score_threshold'] = args.min_score

        # Pass output path for real-time streaming
        context_kwargs['output_path'] = args.output

        # Grabber configuration
        if args.no_grabbers:
            context_kwargs['grabbers_enabled'] = False
        elif args.grabbers is not None:
            # --grabbers with no args = all enabled; with args = specific modules
            context_kwargs['grabbers_enabled'] = True
            if args.grabbers:
                context_kwargs['enabled_grabbers'] = args.grabbers

        context = ScanContext(target_paths, **context_kwargs)

        # Execute scan — streaming reporter writes findings in real-time
        scanner = TreasureScanner(context)
        results = scanner.scan()

        logger.info(f"Results saved to {args.output}")

        # Print summary unless quiet
        if not args.quiet:
            print_summary(results)

        # Exit code based on findings
        if results.critical_findings:
            return 2  # Critical findings found
        elif results.high_findings:
            return 1  # High-value findings found
        else:
            return 0  # Normal completion

    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose >= 2:
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())