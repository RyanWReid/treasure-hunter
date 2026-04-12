"""Tests for entropy analysis module."""

from treasure_hunter.entropy import (
    find_high_entropy_strings,
    shannon_entropy,
    string_entropy,
)


class TestShannonEntropy:
    def test_empty_data(self):
        assert shannon_entropy(b'') == 0.0

    def test_uniform_data(self):
        # All same byte → zero entropy
        assert shannon_entropy(b'\x00' * 100) == 0.0

    def test_random_data_high_entropy(self):
        # 256 unique bytes → maximum entropy ~8.0
        data = bytes(range(256)) * 4
        ent = shannon_entropy(data)
        assert ent > 7.5

    def test_low_entropy_text(self):
        ent = shannon_entropy(b'aaaaabbbbb')
        assert ent < 2.0

    def test_returns_float(self):
        result = shannon_entropy(b'hello world')
        assert isinstance(result, float)


class TestStringEntropy:
    def test_empty_string(self):
        assert string_entropy('') == 0.0

    def test_repeated_chars(self):
        assert string_entropy('aaaaaaa') == 0.0

    def test_high_entropy_key(self):
        key = 'aK3xR9pQ2mN7wL5vB8cY1jT4gH6fD0e'
        ent = string_entropy(key)
        assert ent > 4.0

    def test_normal_text_lower_entropy(self):
        text = 'the quick brown fox jumps over the lazy dog'
        ent = string_entropy(text)
        assert ent < 4.5


class TestFindHighEntropyStrings:
    def test_finds_api_key(self):
        content = 'API_KEY=aK3xR9pQ2mN7wL5vB8cY1jT4gH6fD0eXyZ'
        results = find_high_entropy_strings(content, min_length=16, threshold=4.0)
        assert len(results) >= 1
        assert results[0][1] > 4.0

    def test_skips_comments(self):
        content = '# SECRET=aK3xR9pQ2mN7wL5vB8cY1jT4gH6fD0eXyZ'
        results = find_high_entropy_strings(content, min_length=16, threshold=4.0)
        assert len(results) == 0

    def test_respects_max_results(self):
        content = '\n'.join(
            f'KEY_{i}=aK3xR9pQ2mN7wL5vB8cY1jT4gH6fD{i:02d}eXyZ'
            for i in range(20)
        )
        results = find_high_entropy_strings(content, min_length=16, threshold=3.5, max_results=3)
        assert len(results) <= 3

    def test_no_duplicates(self):
        content = 'TOKEN=aK3xR9pQ2mN7wL5vB8cY1jT4gH6fD0eXyZ'
        results = find_high_entropy_strings(content, min_length=16, threshold=3.0)
        tokens = [r[0] for r in results]
        assert len(tokens) == len(set(tokens))

    def test_empty_content(self):
        assert find_high_entropy_strings('') == []

    def test_normal_text_no_hits(self):
        content = 'This is a normal config file with boring values.\nname = test\ncount = 42'
        results = find_high_entropy_strings(content, min_length=20, threshold=4.5)
        assert len(results) == 0
