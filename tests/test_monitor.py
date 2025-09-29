import pytest

from monitor import (
    DiffResult,
    DiscordNotifier,
    stable_fingerprint,
    diff_lists,
    normalize_js_url,
    normalize_url,
)


def test_stable_fingerprint_order_independent():
    items_a = ["https://example.com/a", "https://example.com/b"]
    items_b = list(reversed(items_a))
    assert stable_fingerprint(items_a) == stable_fingerprint(items_b)


def test_diff_lists_limits_changes():
    old = [f"/old/{i}" for i in range(12)]
    new = [f"/new/{i}" for i in range(12)]
    diff = diff_lists(old, new)
    assert len(diff.added) == 10
    assert len(diff.removed) == 10


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/path?utm_source=test&token=1", "https://example.com/path?token=1"),
        ("//cdn.example.com/app.js", "https://cdn.example.com/app.js"),
    ],
)
def test_normalize_url_strips_tracking(raw, expected):
    assert normalize_url(raw, "https://example.com") == expected


def test_normalize_js_url_filters_cookies():
    assert (
        normalize_js_url("https://example.com/set_cookie?session=1", "https://example.com")
        is None
    )


class DummyClient:
    def __init__(self):
        self.payloads = []

    async def post(self, url, json, timeout):  # pragma: no cover - exercised via notifier
        self.payloads.append((url, json, timeout))


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_discord_notifier_payload_structure():
    client = DummyClient()
    notifier = DiscordNotifier(client, "https://discord.test/webhook")
    diff = DiffResult(added=["/new"], removed=["/old"])
    await notifier.send(
        title="Endpoint change",
        alert_type="new-endpoint",
        domain="example.com",
        diff=diff,
        confidence=0.9,
        source_url="https://example.com",
        file_url="https://example.com/app.js",
    )
    assert client.payloads
    _, payload, _ = client.payloads[0]
    embed = payload["embeds"][0]
    field_names = {field["name"] for field in embed["fields"]}
    assert {"Type", "Domain", "Confidence", "Source", "File"}.issubset(field_names)
    assert embed["title"] == "Endpoint change"
