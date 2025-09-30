#!/usr/bin/env python3
"""Asynchronous content monitoring script.

This script keeps everything in-memory and aims to discover newly added
domains, endpoints and URLs referenced from JavaScript sources.  It sends a
compact alert to Discord whenever a meaningful change is confirmed.
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import re
import sys
import time
from collections import OrderedDict, defaultdict
from contextlib import asynccontextmanager
from typing import AsyncIterator, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import ParseResult, parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

# -------------------------- configuration structures ----------------------- #


@dataclasses.dataclass
class MonitorConfig:
    webhook_url: str
    concurrency: int = 10
    request_timeout: float = 10.0
    per_host_delay: float = 0.2  # be polite: wait at least 200ms between hits per host
    verification_delay: float = 0.5
    retry_attempts: int = 2
    cache_size: int = 1024  # max number of hashed resources kept in memory (~ few MBs)
    allow_domains: Optional[Set[str]] = None
    deny_domains: Optional[Set[str]] = None
    trusted_third_party: Optional[Set[str]] = None
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) ContentMonitor/1.0 (+https://example.com)"
    )


# ----------------------------- bounded LRU cache --------------------------- #


class BoundedLRU:
    """Simple LRU keeping the memory footprint predictable.

    Keys are strings, values are small dataclasses so a limit of 1024 typically
    consumes < 5 MiB which is acceptable for a VPS worker.
    """

    def __init__(self, max_entries: int) -> None:
        self._max = max_entries
        self._data: OrderedDict[str, "ResourceState"] = OrderedDict()

    def get(self, key: str) -> Optional["ResourceState"]:
        if key not in self._data:
            return None
        value = self._data.pop(key)
        self._data[key] = value
        return value

    def set(self, key: str, value: "ResourceState") -> None:
        if key in self._data:
            self._data.pop(key)
        self._data[key] = value
        while len(self._data) > self._max:
            self._data.popitem(last=False)


@dataclasses.dataclass
class ResourceState:
    fingerprint: str
    items: Tuple[str, ...]
    confirmed_at: float
    confirmations: int


# ----------------------------- rate limiter -------------------------------- #


class PerHostRateLimiter:
    def __init__(self, min_delay: float) -> None:
        self._min_delay = min_delay
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._last_request: Dict[str, float] = defaultdict(lambda: 0.0)

    @asynccontextmanager
    async def wait(self, host: str) -> AsyncIterator[None]:
        lock = self._locks[host]
        async with lock:
            now = time.monotonic()
            elapsed = now - self._last_request[host]
            if elapsed < self._min_delay:
                await asyncio.sleep(self._min_delay - elapsed)
            yield
            self._last_request[host] = time.monotonic()


# --------------------------- helper functions ------------------------------ #


ANCHOR_RE = re.compile(r"<a[^>]+href=\"([^\"]+)\"", re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=\"([^\"]+)\"", re.IGNORECASE)
INLINE_JS_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
# Regex keeps extraction lightweight: avoid full HTML/JS parsing for speed.
URL_IN_JS_RE = re.compile(
    r"(?:(?:https?:)?//[^\s'\"<>]+|['\"]/(?:[^'\"\\]|\\.)+['\"])"
)
COOKIE_LIKE_RE = re.compile(r"cookie|session|csrftoken", re.IGNORECASE)


def _tracking_key(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith("utm_") or lowered in {"timestamp", "ts", "_"}


def _strip_tracking_params(parsed: ParseResult) -> ParseResult:
    params = [
        (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if not _tracking_key(k)
    ]
    cleaned_query = urlencode(params, doseq=True)
    return parsed._replace(query=cleaned_query)


def normalize_url(raw: str, base: str) -> Optional[str]:
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("javascript:"):
        return None
    if raw.startswith("//"):
        raw = "https:" + raw
    try:
        url = urljoin(base, raw)
    except ValueError:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    # remove tracking query params
    sanitized = _strip_tracking_params(parsed)
    return urlunparse(sanitized)


def normalize_js_url(raw: str, base: str) -> Optional[str]:
    candidate = raw.strip("'\"")
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    if candidate.startswith("/"):
        try:
            candidate = urljoin(base, candidate)
        except ValueError:
            return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    if COOKIE_LIKE_RE.search(candidate):
        return None
    sanitized = _strip_tracking_params(parsed)
    return urlunparse(sanitized)


# ---------------------------- hashing helpers ------------------------------ #


def stable_fingerprint(items: Iterable[str]) -> str:
    ordered = sorted(set(items))
    payload = "\n".join(ordered).encode()
    return hashlib.sha256(payload).hexdigest()


@dataclasses.dataclass
class DiffResult:
    added: List[str]
    removed: List[str]


def diff_lists(old: Iterable[str], new: Iterable[str]) -> DiffResult:
    old_set = set(old)
    new_set = set(new)
    return DiffResult(
        added=sorted(new_set - old_set)[:10],  # cap output to keep Discord alert concise
        removed=sorted(old_set - new_set)[:10],
    )


# ---------------------------- Discord alerting ----------------------------- #


class DiscordNotifier:
    def __init__(self, client: httpx.AsyncClient, webhook_url: str) -> None:
        self._client = client
        self._webhook_url = webhook_url

    async def send(
        self,
        title: str,
        alert_type: str,
        domain: str,
        diff: DiffResult,
        confidence: float,
        source_url: str,
        file_url: Optional[str] = None,
    ) -> None:
        summary_bits: List[str] = []
        if diff.added:
            summary_bits.append(f"+ {diff.added[0]}")
        if diff.removed:
            summary_bits.append(f"- {diff.removed[0]}")
        summary = ", ".join(summary_bits) if summary_bits else "No direct diff"
        payload = {
            "username": "content-monitor",
            "embeds": [
                {
                    "title": title,
                    "description": summary,
                    "color": 0x3498DB,
                    "fields": [
                        {"name": "Type", "value": alert_type, "inline": True},
                        {"name": "Domain", "value": domain, "inline": True},
                        {
                            "name": "Confidence",
                            "value": f"{confidence:.2f}",
                            "inline": True,
                        },
                        {
                            "name": "Source",
                            "value": source_url,
                            "inline": False,
                        },
                    ],
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            ],
        }
        if file_url:
            payload["embeds"][0]["fields"].append(
                {"name": "File", "value": file_url, "inline": False}
            )
        await self._client.post(self._webhook_url, json=payload, timeout=10.0)


# ------------------------------- monitoring -------------------------------- #


class DomainMonitor:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self.cache = BoundedLRU(config.cache_size)
        self.rate_limiter = PerHostRateLimiter(config.per_host_delay)
        self.seen_domains: Set[str] = set()

    async def run(self, domains: Iterable[str]) -> None:
        async with httpx.AsyncClient(
            http2=True,
            limits=httpx.Limits(max_connections=self.config.concurrency * 2),
            headers={"User-Agent": self.config.user_agent},
            timeout=self.config.request_timeout,
        ) as client:
            notifier = DiscordNotifier(client, self.config.webhook_url)
            sem = asyncio.Semaphore(self.config.concurrency)

            async def worker(domain: str) -> None:
                async with sem:
                    await self.process_domain(client, notifier, domain)

            await asyncio.gather(*(worker(domain) for domain in domains))

    async def fetch(self, client: httpx.AsyncClient, url: str) -> Optional[str]:
        parsed = urlparse(url)
        async with self.rate_limiter.wait(parsed.netloc):
            for attempt in range(self.config.retry_attempts):
                try:
                    resp = await client.get(url, follow_redirects=True)
                except httpx.HTTPError:
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue
                if resp.status_code >= 500:
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue
                if resp.status_code == 404:
                    return None
                content_type = resp.headers.get("content-type", "")
                if "text" not in content_type and "javascript" not in content_type:
                    return None
                return resp.text
        return None

    async def process_domain(
        self, client: httpx.AsyncClient, notifier: DiscordNotifier, domain: str
    ) -> None:
        domain = domain.strip().lower()
        if not domain:
            return
        # Respect allow/deny lists
        if self.config.allow_domains and domain not in self.config.allow_domains:
            return
        if self.config.deny_domains and domain in self.config.deny_domains:
            return
        base_url = f"https://{domain}"
        html = await self.fetch(client, base_url)
        if html is None:
            base_url = f"http://{domain}"
            html = await self.fetch(client, base_url)
        if html is None:
            return
        if domain not in self.seen_domains:
            self.seen_domains.add(domain)
            await notifier.send(
                title=f"New domain online: {domain}",
                alert_type="new-domain",
                domain=domain,
                diff=DiffResult(added=[domain], removed=[]),
                confidence=0.95,
                source_url=base_url,
            )
        await self.process_html(client, notifier, domain, base_url, html)

    async def process_html(
        self,
        client: httpx.AsyncClient,
        notifier: DiscordNotifier,
        domain: str,
        base_url: str,
        html: str,
    ) -> None:
        anchors = self._collect_anchors(html, base_url)
        script_links = self._collect_script_links(html, base_url)
        inline_js_candidates = []
        for block in INLINE_JS_RE.findall(html):
            for match in URL_IN_JS_RE.findall(block):
                normalized = normalize_js_url(match, base_url)
                if normalized:
                    inline_js_candidates.append(normalized)
        await self.check_endpoints(client, notifier, domain, base_url, anchors)
        await self.check_js_urls(
            client, notifier, domain, base_url, script_links, inline_js_candidates
        )

    async def check_endpoints(
        self,
        client: httpx.AsyncClient,
        notifier: DiscordNotifier,
        domain: str,
        base_url: str,
        anchors: List[str],
    ) -> None:
        filtered: List[str] = []
        for url in anchors:
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != urlparse(base_url).netloc:
                # ignore known third parties but allow overrides
                if self.config.trusted_third_party and parsed.netloc in self.config.trusted_third_party:
                    continue
                if self.config.allow_domains and parsed.netloc not in self.config.allow_domains:
                    continue
                if self.config.deny_domains and parsed.netloc in self.config.deny_domains:
                    continue
                if parsed.netloc.endswith(domain):
                    filtered.append(url)
                continue
            filtered.append(url)
        items_tuple = tuple(sorted(set(filtered)))
        fingerprint = stable_fingerprint(items_tuple)
        cache_key = f"endpoint::{domain}"
        previous = self.cache.get(cache_key)
        if previous and previous.fingerprint == fingerprint:
            return
        diff = diff_lists(previous.items if previous else [], items_tuple)
        if not diff.added and not diff.removed:
            return
        confirmed = await self._confirm_endpoints(client, base_url, fingerprint)
        confidence = 0.9 if confirmed else 0.6
        self.cache.set(
            cache_key,
            ResourceState(
                fingerprint=fingerprint,
                items=items_tuple,
                confirmed_at=time.time(),
                confirmations=1 if confirmed else 0,
            ),
        )
        if not confirmed:
            # We still notify but mark lower confidence to avoid missing races.
            diff = diff_lists(previous.items if previous else [], items_tuple)
        await notifier.send(
            title=f"Endpoint change detected on {domain}",
            alert_type="new-endpoint",
            domain=domain,
            diff=diff,
            confidence=confidence,
            source_url=base_url,
        )

    async def check_js_urls(
        self,
        client: httpx.AsyncClient,
        notifier: DiscordNotifier,
        domain: str,
        base_url: str,
        script_links: List[str],
        inline_js_candidates: List[str],
    ) -> None:
        aggregated: List[str] = list(inline_js_candidates)
        for script_url in script_links:
            js_text = await self.fetch(client, script_url)
            if not js_text:
                continue
            matches = URL_IN_JS_RE.findall(js_text)
            for match in matches:
                normalized = normalize_js_url(match, script_url)
                if normalized:
                    aggregated.append(normalized)
        aggregated = [url for url in aggregated if self._is_relevant(domain, url)]
        items_tuple = tuple(sorted(set(aggregated)))
        fingerprint = stable_fingerprint(items_tuple)
        cache_key = f"js::{domain}"
        previous = self.cache.get(cache_key)
        if previous and previous.fingerprint == fingerprint:
            return
        diff = diff_lists(previous.items if previous else [], items_tuple)
        if not diff.added and not diff.removed:
            return
        confirmed = await self._confirm_js(client, base_url, fingerprint)
        self.cache.set(
            cache_key,
            ResourceState(
                fingerprint=fingerprint,
                items=items_tuple,
                confirmed_at=time.time(),
                confirmations=1 if confirmed else 0,
            ),
        )
        target_url = script_links[0] if script_links else base_url
        await notifier.send(
            title=f"JavaScript reference change on {domain}",
            alert_type="changed-js-url",
            domain=domain,
            diff=diff,
            confidence=0.85 if confirmed else 0.6,
            source_url=base_url,
            file_url=target_url,
        )

    def _is_relevant(self, domain: str, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != domain:
            if self.config.trusted_third_party and parsed.netloc in self.config.trusted_third_party:
                return False
            if self.config.deny_domains and parsed.netloc in self.config.deny_domains:
                return False
        return True

    def _collect_anchors(self, html: str, base_url: str) -> List[str]:
        anchors: List[str] = []
        for href in ANCHOR_RE.findall(html):
            normalized = normalize_url(href, base_url)
            if normalized:
                anchors.append(normalized)
        return anchors

    def _collect_script_links(self, html: str, base_url: str) -> List[str]:
        scripts: List[str] = []
        for src in SCRIPT_SRC_RE.findall(html):
            normalized = normalize_url(src, base_url)
            if normalized:
                scripts.append(normalized)
        return scripts

    async def _confirm_endpoints(
        self, client: httpx.AsyncClient, base_url: str, expected_fingerprint: str
    ) -> bool:
        # Lightweight second fetch reduces transient false positives.
        await asyncio.sleep(self.config.verification_delay)
        html = await self.fetch(client, base_url)
        if html is None:
            return False
        refreshed = tuple(sorted(set(self._collect_anchors(html, base_url))))
        return stable_fingerprint(refreshed) == expected_fingerprint

    async def _confirm_js(
        self, client: httpx.AsyncClient, base_url: str, expected_fingerprint: str
    ) -> bool:
        # Re-fetch the page + scripts to ensure the change is persistent.
        await asyncio.sleep(self.config.verification_delay)
        html = await self.fetch(client, base_url)
        if html is None:
            return False
        inline_candidates: List[str] = []
        for block in INLINE_JS_RE.findall(html):
            for match in URL_IN_JS_RE.findall(block):
                normalized = normalize_js_url(match, base_url)
                if normalized:
                    inline_candidates.append(normalized)
        refreshed_scripts = self._collect_script_links(html, base_url)
        aggregated: List[str] = list(inline_candidates)
        for script_url in refreshed_scripts:
            js_text = await self.fetch(client, script_url)
            if not js_text:
                continue
            for match in URL_IN_JS_RE.findall(js_text):
                normalized = normalize_js_url(match, script_url)
                if normalized:
                    aggregated.append(normalized)
        domain = urlparse(base_url).netloc
        aggregated = [url for url in aggregated if self._is_relevant(domain, url)]
        refreshed_fingerprint = stable_fingerprint(aggregated)
        return refreshed_fingerprint == expected_fingerprint


# ------------------------------- CLI parsing ------------------------------- #


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor domains for surface changes")
    parser.add_argument("--domain", help="Single domain to monitor")
    parser.add_argument("--domains-file", help="File containing domains, one per line")
    parser.add_argument("--webhook", required=True, help="Discord webhook URL")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--per-host-delay", type=float, default=0.2)
    parser.add_argument("--verification-delay", type=float, default=0.5)
    parser.add_argument("--cache-size", type=int, default=1024)
    parser.add_argument(
        "--trusted-third-party",
        nargs="*",
        default=[],
        help="Domains considered noise when seen in JS references",
    )
    parser.add_argument("--allow-domains", nargs="*", default=None)
    parser.add_argument("--deny-domains", nargs="*", default=None)
    return parser.parse_args(argv)


def gather_domains(args: argparse.Namespace) -> List[str]:
    domains: Set[str] = set()
    if args.domain:
        domains.add(args.domain)
    if args.domains_file:
        try:
            for line in open(args.domains_file, "r", encoding="utf-8"):
                domains.add(line.strip())
        except OSError:
            raise SystemExit(f"Unable to read domains file: {args.domains_file}")
    if not domains:
        raise SystemExit("No domains supplied")
    return sorted(domains)


async def main_async(argv: List[str]) -> None:
    args = parse_args(argv)
    domains = gather_domains(args)
    config = MonitorConfig(
        webhook_url=args.webhook,
        concurrency=args.concurrency,
        per_host_delay=args.per_host_delay,
        verification_delay=args.verification_delay,
        cache_size=args.cache_size,
        allow_domains=set(args.allow_domains) if args.allow_domains else None,
        deny_domains=set(args.deny_domains) if args.deny_domains else None,
        trusted_third_party=set(args.trusted_third_party) if args.trusted_third_party else None,
    )
    monitor = DomainMonitor(config)
    await monitor.run(domains)


def main() -> None:
    asyncio.run(main_async(sys.argv[1:]))


if __name__ == "__main__":
    main()
