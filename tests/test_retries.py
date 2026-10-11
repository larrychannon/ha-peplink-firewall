"""Temporary IC2 failures recover without replaying ambiguous router writes."""

import asyncio
from unittest.mock import patch

import pytest
from aiohttp import ClientSession, web

from custom_components.peplink_firewall.api import PeplinkError, TransientError
from tests.test_api import TAG, client


@pytest.fixture(autouse=True)
def fast_backoff():
    with patch("custom_components.peplink_firewall.api.READ_RETRY_DELAYS", (0, 0, 0)):
        yield


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
async def test_temporary_http_read_recovers(router, status):
    router.faults["/api/config.firewall"] = [web.Response(status=status)]
    async with ClientSession() as session:
        assert (await client(session, router).read_snapshot()).active
    assert sum(path.endswith("config.firewall") for _, path, _ in router.requests) == 2
    assert not router.saves and router.applies == 0


@pytest.mark.parametrize(
    "path,body",
    [
        ("/api/config.firewall", "<html>Temporary gateway page</html>"),
        ("/api/config.firewall", '{"stat":'),
        ("/cgi-bin/MANGA/chkactivate.cgi", "<response>"),
        ("/cgi-bin/MANGA/chkactivate.cgi", "<html>Temporary gateway page</html>"),
    ],
)
async def test_incomplete_read_response_recovers(router, path, body):
    router.faults[path] = [web.Response(text=body)]
    async with ClientSession() as session:
        assert (await client(session, router).read_snapshot()).active


async def test_timeout_recovers(router):
    async with ClientSession() as session:
        original = session.request
        failed = False

        def request(method, url, **kwargs):
            nonlocal failed
            if url.endswith("config.firewall") and not failed:
                failed = True
                raise TimeoutError
            return original(method, url, **kwargs)

        with patch.object(session, "request", side_effect=request):
            assert (await client(session, router).read_snapshot()).active
        assert failed


async def test_retry_exhaustion_is_bounded(router):
    router.faults["/api/config.firewall"] = [web.Response(status=503) for _ in range(8)]
    async with ClientSession() as session:
        with pytest.raises(TransientError):
            await client(session, router).read_snapshot()
    assert sum(path.endswith("config.firewall") for _, path, _ in router.requests) == 4


async def test_permanent_error_is_not_retried(router):
    router.faults["/api/config.firewall"] = [web.Response(status=404)]
    async with ClientSession() as session:
        with pytest.raises(PeplinkError, match="404"):
            await client(session, router).read_snapshot()
    assert sum(path.endswith("config.firewall") for _, path, _ in router.requests) == 1


@pytest.mark.parametrize("path", ["/cgi-bin/MANGA/admin.cgi", "/api/cmd.config.apply"])
async def test_temporary_write_failure_is_not_replayed(router, path):
    router.faults[path] = [web.Response(status=503)]
    async with ClientSession() as session:
        with pytest.raises(TransientError):
            await client(session, router).set_group_enabled(TAG, False)
    assert sum(request_path == path for _, request_path, _ in router.requests) == 1


async def test_retry_deadline(router):
    router.faults["/api/config.firewall"] = [web.Response(status=503)]
    async with ClientSession() as session:
        with (
            patch("custom_components.peplink_firewall.api.READ_RETRY_TIMEOUT", 0.02),
            patch("custom_components.peplink_firewall.api.READ_RETRY_DELAYS", (1, 2, 4)),
            pytest.raises(TransientError, match="deadline"),
        ):
            await client(session, router).read_snapshot()


async def test_cancellation_during_backoff_propagates(router):
    async with ClientSession() as session:
        api = client(session, router)
        waiting = asyncio.Event()

        async def fail():
            waiting.set()
            raise TransientError("Temporary")

        with patch("custom_components.peplink_firewall.api.READ_RETRY_DELAYS", (30, 30, 30)):
            task = asyncio.create_task(api._read_with_retry(fail, "test read"))
            await waiting.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


async def test_temporary_token_service_failure_recovers(router):
    router.faults["/oauth"] = [web.Response(status=503)]
    async with ClientSession() as session:
        assert (await client(session, router).read_snapshot()).active
    assert len(router.grants) == 1
    assert sum(path == "/oauth" for _, path, _ in router.requests) == 2
