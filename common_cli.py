"""CLI helper for the custom ffuf wrapper.

This module implements the logic used by the `common` executable.  It is
responsible for invoking ffuf, collecting the streamed JSON output, grouping
responses by their metadata and HTTP body, and printing only the unique hits.

The module is intentionally importable so that its core components can be unit
tested without the ffuf binary being present.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


@dataclass
class UniqueEntry:
    """Represents a unique response discovered during fuzzing."""

    status: int
    length: int
    words: int
    lines: int
    content_hash: str
    result: Dict[str, object]
    urls: List[str] = field(default_factory=list)
    count: int = 0
    body_path: Optional[Path] = None

    def add_url(self, url: str) -> None:
        self.urls.append(url)
        self.count = len(self.urls)


class ResultAggregator:
    """Tracks unique ffuf results and gathers summary statistics."""

    def __init__(self) -> None:
        self.entries: "OrderedDict[Tuple[int, int, int, int, str], UniqueEntry]" = OrderedDict()
        self.size_index: Dict[Tuple[int, int, int, int], Dict[str, object]] = defaultdict(
            lambda: {"count": 0, "keys": set(), "urls": []}
        )
        self.total_results: int = 0
        self.duplicate_results: int = 0

    def add_result(
        self, result: Dict[str, object], content_hash: str, body_path: Optional[Path]
    ) -> Tuple[bool, UniqueEntry]:
        status = int(result.get("status", 0))
        length = int(result.get("length", 0))
        words = int(result.get("words", 0))
        lines = int(result.get("lines", 0))
        url = str(result.get("url", ""))

        size_key = (status, length, words, lines)
        unique_key = (status, length, words, lines, content_hash)
        group = self.size_index[size_key]
        group["count"] = int(group["count"]) + 1
        group_urls = group.setdefault("urls", [])
        group_urls.append(url)
        group_keys: set = group.setdefault("keys", set())
        group_keys.add(unique_key)

        self.total_results += 1

        entry = self.entries.get(unique_key)
        if entry is None:
            entry = UniqueEntry(
                status=status,
                length=length,
                words=words,
                lines=lines,
                content_hash=content_hash,
                result=result,
                urls=[],
                body_path=body_path,
            )
            self.entries[unique_key] = entry

        else:
            self.duplicate_results += 1

        entry.add_url(url)
        return entry.count == 1, entry

    def identical_groups(self, status_code: Optional[int] = None) -> List[UniqueEntry]:
        groups: List[UniqueEntry] = []
        for entry in self.entries.values():
            if entry.count <= 1:
                continue
            if status_code is None or entry.status == status_code:
                groups.append(entry)
        return groups

    def metric_collisions(self) -> List[Dict[str, object]]:
        collisions: List[Dict[str, object]] = []
        for (status, length, words, lines), info in self.size_index.items():
            count = int(info["count"])
            keys = info.get("keys", set())
            if len(keys) <= 1:
                continue
            sample_urls: List[str] = []
            for key in keys:
                entry = self.entries.get(key)
                if entry is not None and entry.urls:
                    sample_urls.append(entry.urls[0])
            collisions.append(
                {
                    "status": status,
                    "length": length,
                    "words": words,
                    "lines": lines,
                    "unique_variations": len(keys),
                    "count": count,
                    "sample_urls": sample_urls,
                }
            )
        return collisions


def decode_inputs(input_map: Optional[Dict[str, object]]) -> Dict[str, str]:
    if not isinstance(input_map, dict):
        return {}
    decoded: Dict[str, str] = {}
    for key, value in input_map.items():
        decoded_value = ""
        if isinstance(value, str):
            try:
                decoded_bytes = base64.b64decode(value, validate=True)
                decoded_value = decoded_bytes.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                decoded_value = value
        elif isinstance(value, (bytes, bytearray)):
            decoded_value = bytes(value).decode("utf-8", errors="replace")
        else:
            decoded_value = str(value)
        decoded[key] = decoded_value
    return decoded


def status_label(status: int) -> str:
    try:
        phrase = HTTPStatus(status).phrase
        return f"{status} {phrase}"
    except Exception:
        return str(status)


def option_present(args: Sequence[str], *names: str) -> bool:
    for token in args:
        for name in names:
            if token == name:
                return True
            if name.startswith("--") and token.startswith(f"{name}="):
                return True
            if name.startswith("-") and not name.startswith("--"):
                if token.startswith(f"{name}="):
                    return True
                if token.startswith(name) and len(token) > len(name) and token[len(name)] != "-":
                    return True
    return False


def extract_option_value(args: Sequence[str], *names: str) -> Optional[str]:
    for idx, token in enumerate(args):
        for name in names:
            if token == name:
                if idx + 1 < len(args):
                    return args[idx + 1]
                return ""
            if token.startswith(f"{name}="):
                return token.split("=", 1)[1]
    return None


def normalize_ffuf_args(ffuf_args: Sequence[str]) -> Tuple[List[str], Optional[str], List[str]]:
    filtered: List[str] = []
    output_dir: Optional[str] = None
    warnings: List[str] = []

    i = 0
    while i < len(ffuf_args):
        token = ffuf_args[i]

        if token in {"-json", "--json"}:
            i += 1
            continue
        if token in {"-ac", "--auto-calibrate"}:
            warnings.append("Ignoring auto-calibrate flag (-ac) because it conflicts with custom deduplication.")
            i += 1
            continue
        if token in {"-t", "--threads"}:
            i += 2
            continue
        if token.startswith("-t=") or token.startswith("--threads="):
            i += 1
            continue
        if token in {"-fw", "--filter-words"}:
            i += 2
            continue
        if token.startswith("-fw=") or token.startswith("--filter-words="):
            i += 1
            continue
        if token in {"-od", "--output-directory"}:
            if i + 1 < len(ffuf_args):
                output_dir = ffuf_args[i + 1]
                i += 2
            else:
                warnings.append("Missing value for -od/--output-directory")
                i += 1
            continue
        if token.startswith("-od=") or token.startswith("--output-directory="):
            output_dir = token.split("=", 1)[1]
            i += 1
            continue

        filtered.append(token)
        i += 1

    return filtered, output_dir, warnings


def read_stdin_wordlist() -> Optional[Path]:
    if sys.stdin.isatty():
        return None
    data = sys.stdin.read()
    if not data:
        return None
    temp = tempfile.NamedTemporaryFile(prefix="common_wordlist_", suffix=".txt", delete=False)
    temp.write(data.encode("utf-8"))
    temp.flush()
    temp.close()
    return Path(temp.name)


def compute_result_hash(result: Dict[str, object], output_dir: Path) -> Tuple[str, Optional[Path]]:
    resultfile = result.get("resultfile")
    if isinstance(resultfile, str) and resultfile:
        candidate = Path(resultfile)
        if not candidate.is_absolute():
            candidate = output_dir / candidate
        if candidate.exists():
            try:
                content = candidate.read_bytes()
            except OSError:
                content = b""
            if content:
                digest = hashlib.sha256(content).hexdigest()
                return digest, candidate
    key = "|".join(
        [
            str(result.get("status", "")),
            str(result.get("length", "")),
            str(result.get("words", "")),
            str(result.get("lines", "")),
            str(result.get("url", "")),
        ]
    )
    return hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest(), None


def format_duration(raw_duration: object) -> Optional[str]:
    if raw_duration is None:
        return None
    if isinstance(raw_duration, (int, float)):
        return f"{raw_duration}"
    return str(raw_duration)


def print_unique_result(entry: UniqueEntry) -> None:
    res = entry.result
    decoded_inputs = decode_inputs(res.get("input"))
    location = res.get("url", "")
    redirect = res.get("redirectlocation")
    duration = format_duration(res.get("duration"))

    summary = [
        f"Status: {status_label(entry.status)}",
        f"Size: {entry.length} bytes",
        f"Words: {entry.words}",
        f"Lines: {entry.lines}",
    ]
    if duration:
        summary.append(f"Duration: {duration}")

    print(f"[+] Unique response -> {' | '.join(summary)}")
    if location:
        print(f"    URL: {location}")
    if decoded_inputs:
        inputs_str = ", ".join(f"{k}={v}" for k, v in decoded_inputs.items())
        print(f"    Inputs: {inputs_str}")
    if redirect:
        print(f"    Redirect: {redirect}")
    if entry.body_path:
        print(f"    Saved body: {entry.body_path}")


def print_duplicate_notice(entry: UniqueEntry, new_url: str) -> None:
    print(
        "[-] Filtered duplicate -> "
        f"Status {entry.status}, Size {entry.length}, Words {entry.words}, Lines {entry.lines} (hash {entry.content_hash[:10]}...)"
    )
    print(f"    Existing sample: {entry.urls[0]}")
    print(f"    Duplicate path : {new_url}")


def print_summary(aggregator: ResultAggregator) -> None:
    print("\n===== Summary =====")
    print(f"Total responses processed : {aggregator.total_results}")
    print(f"Unique responses retained : {len(aggregator.entries)}")
    print(f"Duplicates filtered       : {aggregator.duplicate_results}")

    identical_404 = [entry for entry in aggregator.identical_groups(404)]
    identical_other = [entry for entry in aggregator.identical_groups(None) if entry.status != 404]

    if identical_404:
        print("\nFiltered identical 404 responses (noise removed):")
        for entry in identical_404:
            extra = entry.count - 1
            sample = entry.urls[0]
            print(
                f"  - {extra} additional hits matched Status 404 | Size {entry.length} | Words {entry.words} | Lines {entry.lines}."
            )
            print(f"    Representative URL: {sample}")

    if identical_other:
        print("\nRepetitive non-404 responses to verify manually:")
        for entry in identical_other:
            extra = entry.count - 1
            sample = entry.urls[0]
            other_urls = entry.urls[1:]
            print(
                f"  - Status {entry.status} repeated {entry.count} times with identical body (Size {entry.length}, Words {entry.words}, Lines {entry.lines})."
            )
            print(f"    Review this sample in browser: {sample}")
            if other_urls:
                preview = ", ".join(other_urls[:3])
                if len(other_urls) > 3:
                    preview += ", ..."
                print(f"    Additional matches: {preview}")

    collisions = aggregator.metric_collisions()
    if collisions:
        print("\nUnique variations sharing identical metrics (worth double checking):")
        for item in collisions:
            status = item["status"]
            size = item["length"]
            words = item["words"]
            lines = item["lines"]
            unique_variations = item["unique_variations"]
            count = item["count"]
            samples = item["sample_urls"]
            print(
                f"  - Status {status} | Size {size} | Words {words} | Lines {lines} -> {unique_variations} unique variants across {count} hits."
            )
            if samples:
                preview = ", ".join(samples[:3])
                if len(samples) > 3:
                    preview += ", ..."
                print(f"    Samples: {preview}")


def run_ffuf(cmd: Sequence[str], output_dir: Path, show_duplicates: bool) -> ResultAggregator:
    aggregator = ResultAggregator()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"Unable to start ffuf: {exc}")

    def relay_stderr(stream: Iterable[str]) -> None:
        for chunk in stream:
            sys.stderr.write(chunk)
        sys.stderr.flush()

    stderr_thread = threading.Thread(target=relay_stderr, args=(iter(proc.stderr.readline, "")), daemon=True)
    stderr_thread.start()

    try:
        stdout_iter: Iterator[str] = iter(proc.stdout.readline, "")
        for raw_line in stdout_iter:
            line = raw_line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                sys.stderr.write(f"[common] Skipping non-JSON line from ffuf: {line}\n")
                continue
            content_hash, body_path = compute_result_hash(result, output_dir)
            is_unique, entry = aggregator.add_result(result, content_hash, body_path)
            if is_unique:
                print_unique_result(entry)
            elif show_duplicates and entry.urls:
                print_duplicate_notice(entry, entry.urls[-1])
        proc.stdout.close()
        returncode = proc.wait()
        stderr_thread.join(timeout=0.2)
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(timeout=5)
        raise

    if returncode not in (0, 1):
        sys.stderr.write(f"ffuf exited with status {returncode}\n")
    return aggregator


def build_command(args: argparse.Namespace, ffuf_args: Sequence[str], output_dir: Path, wordlist_path: Optional[Path]) -> List[str]:
    cmd: List[str] = [args.ffuf_binary, "-json", "-u", args.url, "-t", str(args.threads), "-fw", args.filter_words]

    if not option_present(ffuf_args, "-mc", "--match-codes"):
        cmd.extend(["-mc", "all"])
    if not option_present(ffuf_args, "-r", "--recursion"):
        cmd.append("-r")
    if not option_present(ffuf_args, "-c", "--color"):
        cmd.append("-c")

    cmd.extend(["-od", str(output_dir)])

    if wordlist_path is not None:
        cmd.extend(["-w", str(wordlist_path)])
    elif not option_present(ffuf_args, "-w", "--wordlist"):
        cmd.extend(["-w", args.default_wordlist])

    cmd.extend(ffuf_args)
    return cmd


def parse_args(argv: Optional[Sequence[str]]) -> Tuple[argparse.Namespace, List[str]]:
    parser = argparse.ArgumentParser(
        prog="common",
        description="Wrapper around ffuf that keeps only unique responses.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=True,
    )
    parser.add_argument("url", help="Target URL containing the FUZZ keyword")
    parser.add_argument("threads", type=int, help="Number of concurrent ffuf threads")
    parser.add_argument("filter_words", help="Initial word-count filter to ignore obvious noise")
    parser.add_argument(
        "-W",
        "--default-wordlist",
        default=DEFAULT_WORDLIST,
        help="Fallback wordlist used when -w is not supplied and no piped input is detected",
    )
    parser.add_argument(
        "--ffuf-binary",
        default="ffuf",
        help="Path to the ffuf executable",
    )
    parser.add_argument(
        "--show-duplicates",
        action="store_true",
        help="Log duplicate matches as they are filtered out",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Preserve temporary files produced by ffuf",
    )

    args, remaining = parser.parse_known_args(argv)
    return args, list(remaining)


def main(argv: Optional[Sequence[str]] = None) -> None:
    args, ffuf_raw_args = parse_args(argv)

    if args.threads < 1:
        raise SystemExit("Threads value must be a positive integer")

    if shutil.which(args.ffuf_binary) is None:
        raise SystemExit(f"ffuf executable not found: {args.ffuf_binary}")

    wordlist_from_stdin = read_stdin_wordlist()

    normalized_args, output_dir_value, warnings = normalize_ffuf_args(ffuf_raw_args)
    for warning in warnings:
        sys.stderr.write(f"[common] {warning}\n")

    created_output_dir = False
    if output_dir_value:
        output_dir_path = Path(output_dir_value).expanduser().resolve()
        output_dir_path.mkdir(parents=True, exist_ok=True)
    else:
        output_dir_path = Path(tempfile.mkdtemp(prefix="common_ffuf_"))
        created_output_dir = True

    if wordlist_from_stdin is None and not option_present(normalized_args, "-w", "--wordlist"):
        wordlist_path: Optional[Path] = Path(args.default_wordlist)
    elif wordlist_from_stdin is not None:
        wordlist_path = wordlist_from_stdin
    else:
        wordlist_path = None

    cmd = build_command(args, normalized_args, output_dir_path, wordlist_path)

    try:
        aggregator = run_ffuf(cmd, output_dir_path, args.show_duplicates)
    finally:
        if not args.keep_temp and wordlist_from_stdin is not None:
            try:
                os.unlink(wordlist_from_stdin)
            except OSError:
                pass
        if not args.keep_temp and created_output_dir:
            shutil.rmtree(output_dir_path, ignore_errors=True)

    print_summary(aggregator)


if __name__ == "__main__":
    main()
