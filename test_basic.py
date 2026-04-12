#!/usr/bin/env python3
"""
Basic functionality test for treasure-hunter.

This test creates some sample files and verifies that the scanner
can detect them correctly based on the value taxonomy.
"""

import tempfile
import os
from pathlib import Path
from treasure_hunter import TreasureScanner, ScanContext


def test_basic_functionality():
    """Test that the scanner can detect valuable files."""
    print("🧪 Running basic functionality test...")

    # Create a temporary directory with test files
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create some test files that should trigger findings
        test_files = {
            'passwords.txt': 'username: admin\npassword: secret123',
            'id_rsa': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...',
            'database.kdbx': b'binary_keepass_data',
            'config.env': 'AWS_ACCESS_KEY_ID=AKIAEXAMPLE123456789\nAWS_SECRET_ACCESS_KEY=secret',
            'remote.rdp': '[connection]\nhost=192.168.1.100',
            'backup.sql': 'CREATE TABLE users (id, username, password);',
            'normal_file.txt': 'This is just a normal text file.'
        }

        # Create the test files
        for filename, content in test_files.items():
            file_path = temp_path / filename
            if isinstance(content, str):
                file_path.write_text(content, encoding='utf-8')
            else:
                file_path.write_bytes(content)

        print(f"📁 Created {len(test_files)} test files in {temp_dir}")

        # Run scan
        context = ScanContext(
            target_paths=[str(temp_path)],
            max_threads=2,
            time_limit=30,  # 30 seconds max
            min_score_threshold=20  # Lower threshold for testing
        )

        scanner = TreasureScanner(context)
        results = scanner.scan()

        # Verify results
        print(f"📊 Scan completed:")
        print(f"   Files scanned: {results.total_files_scanned}")
        print(f"   Findings: {len(results.findings)}")
        print(f"   Errors: {len(results.errors)}")

        # Check for expected findings
        expected_findings = {'passwords.txt', 'id_rsa', 'database.kdbx', 'config.env', 'remote.rdp', 'backup.sql'}
        found_files = set()

        print(f"\n🔍 Detailed findings:")
        for finding in sorted(results.findings, key=lambda x: x.total_score, reverse=True):
            filename = Path(finding.file_path).name
            found_files.add(filename)

            severity_emoji = {
                5: "🚨", 4: "🔴", 3: "🟡", 2: "🟢", 1: "ℹ️"
            }.get(finding.severity.value, "❓")

            print(f"   {severity_emoji} {filename} (score: {finding.total_score})")

            for signal in finding.signals:
                print(f"      - {signal.description}")

        # Verify we found most of the valuable files
        missing_files = expected_findings - found_files
        if missing_files:
            print(f"\n⚠️  Expected but not found: {missing_files}")

        # Should NOT find normal_file.txt (unless it has surprising signals)
        if 'normal_file.txt' in found_files:
            print(f"⚠️  Unexpectedly found: normal_file.txt")

        success = len(found_files) >= 4  # At least 4 of 6 valuable files found
        print(f"\n{'✅ Test PASSED' if success else '❌ Test FAILED'}")

        return success


def test_cli_help():
    """Test that the CLI interface can be imported and shows help."""
    print("\n🧪 Testing CLI interface...")

    try:
        from treasure_hunter.cli import create_parser

        parser = create_parser()
        help_text = parser.format_help()

        # Verify key elements are in help
        required_elements = [
            'treasure-hunter',
            'smash',
            'triage',
            'full',
            'stealth',
            'SCAN PROFILES'
        ]

        missing_elements = []
        for element in required_elements:
            if element not in help_text:
                missing_elements.append(element)

        if missing_elements:
            print(f"❌ Missing help elements: {missing_elements}")
            return False
        else:
            print("✅ CLI help format looks good")
            return True

    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        return False


if __name__ == '__main__':
    print("🏴‍☠️  TREASURE-HUNTER Basic Test Suite")
    print("="*50)

    all_passed = True

    # Test basic functionality
    try:
        all_passed &= test_basic_functionality()
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        all_passed = False

    # Test CLI
    try:
        all_passed &= test_cli_help()
    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        all_passed = False

    print("\n" + "="*50)
    if all_passed:
        print("🎉 All tests PASSED!")
        exit(0)
    else:
        print("💥 Some tests FAILED!")
        exit(1)