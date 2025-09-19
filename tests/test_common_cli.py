import hashlib
from pathlib import Path

import pytest

import common_cli


def test_decode_inputs_base64_and_plain():
    data = {"FUZZ": "L2FkbWlu", "RAW": "text"}
    decoded = common_cli.decode_inputs(data)
    assert decoded["FUZZ"] == "/admin"
    assert decoded["RAW"] == "text"


def test_option_present_variants():
    args = ["-H", "Header: test", "-w", "list.txt", "--wordlist=alt.txt"]
    assert common_cli.option_present(args, "-w")
    assert common_cli.option_present(args, "--wordlist")
    assert not common_cli.option_present(args, "-x")


def test_normalize_ffuf_args_strips_conflicting_flags():
    args = ["-json", "-ac", "-t", "50", "-fw", "123", "-od", "out", "-H", "X: 1"]
    filtered, output_dir, warnings = common_cli.normalize_ffuf_args(args)
    assert filtered == ["-H", "X: 1"]
    assert output_dir == "out"
    assert any("auto-calibrate" in warn for warn in warnings)


def test_compute_result_hash_prefers_file(tmp_path: Path):
    body = tmp_path / "body"
    body.write_text("response body")
    result = {"resultfile": body.name, "status": 200, "length": 42, "words": 3, "lines": 1, "url": "http://example"}
    digest, path = common_cli.compute_result_hash(result, tmp_path)
    assert path == body
    assert digest == hashlib.sha256(b"response body").hexdigest()


def test_result_aggregator_tracks_uniques(tmp_path: Path):
    aggregator = common_cli.ResultAggregator()
    base_result = {
        "status": 200,
        "length": 100,
        "words": 10,
        "lines": 5,
        "url": "http://example/FUZZ",
    }
    unique_one = base_result | {"url": "http://example/a"}
    unique_two = base_result | {"url": "http://example/b"}
    hash1, _ = common_cli.compute_result_hash({**unique_one, "resultfile": ""}, tmp_path)
    hash2, _ = common_cli.compute_result_hash({**unique_two, "resultfile": ""}, tmp_path)

    is_unique, entry1 = aggregator.add_result(unique_one, hash1, None)
    assert is_unique
    assert entry1.count == 1

    is_unique, entry2 = aggregator.add_result(unique_two, hash1, None)
    assert not is_unique
    assert entry2.count == 2

    is_unique, entry3 = aggregator.add_result({**unique_two, "url": "http://example/c"}, hash2, None)
    assert is_unique
    assert entry3.count == 1

    collisions = aggregator.metric_collisions()
    assert collisions[0]["unique_variations"] == 2
