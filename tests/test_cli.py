"""Tests for CLI interface and scan profiles."""

from treasure_hunter.cli import (
    SCAN_PROFILES,
    create_parser,
    filter_existing_paths,
    get_default_targets,
)


class TestScanProfiles:
    def test_all_profiles_exist(self):
        assert set(SCAN_PROFILES.keys()) == {'smash', 'triage', 'full', 'stealth'}

    def test_smash_is_fastest(self):
        assert SCAN_PROFILES['smash'].config['time_limit'] < SCAN_PROFILES['triage'].config['time_limit']

    def test_stealth_fewest_threads(self):
        assert SCAN_PROFILES['stealth'].config['max_threads'] < SCAN_PROFILES['full'].config['max_threads']

    def test_full_no_time_limit(self):
        assert SCAN_PROFILES['full'].config['time_limit'] is None

    def test_profiles_have_required_keys(self):
        required = {'max_threads', 'min_score_threshold', 'max_file_size', 'content_sample_size'}
        for name, profile in SCAN_PROFILES.items():
            missing = required - set(profile.config.keys())
            assert not missing, f"Profile '{name}' missing keys: {missing}"


class TestParser:
    def test_default_profile(self):
        parser = create_parser()
        args = parser.parse_args([])
        assert args.profile == 'smash'

    def test_custom_profile(self):
        parser = create_parser()
        args = parser.parse_args(['-p', 'full'])
        assert args.profile == 'full'

    def test_custom_targets(self):
        parser = create_parser()
        args = parser.parse_args(['-t', '/tmp', '/var'])
        assert args.targets == ['/tmp', '/var']

    def test_output_default(self):
        parser = create_parser()
        args = parser.parse_args([])
        assert args.output == 'treasure-hunter-results.jsonl'

    def test_quiet_flag(self):
        parser = create_parser()
        args = parser.parse_args(['-q'])
        assert args.quiet is True

    def test_help_text_contains_profiles(self):
        parser = create_parser()
        help_text = parser.format_help()
        for name in ['smash', 'triage', 'full', 'stealth']:
            assert name in help_text


class TestFilterExistingPaths:
    def test_filters_nonexistent(self):
        result = filter_existing_paths(['/nonexistent/path/12345'])
        assert result == []

    def test_keeps_existing(self):
        result = filter_existing_paths(['/tmp'])
        assert '/tmp' in result

    def test_mixed(self):
        result = filter_existing_paths(['/tmp', '/nonexistent/path/12345'])
        assert len(result) == 1


class TestGetDefaultTargets:
    def test_returns_list(self):
        targets = get_default_targets()
        assert isinstance(targets, list)
        assert len(targets) > 0

    def test_paths_are_strings(self):
        for target in get_default_targets():
            assert isinstance(target, str)
