"""Async router transport, authentication, and verified outbound-only writes."""

import asyncio
import json
import logging
import time
import xml.etree.ElementTree as ET
from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from aiohttp import (
    ClientConnectionError,
    ClientError,
    ClientPayloadError,
    ClientSession,
    ClientSSLError,
    ClientTimeout,
)

from .const import IC2_TOKEN_URL, MODE_DIRECT, MODE_IC2, USER_AGENT
from .rules import RuleError, matching_rules, rule_form

LOGGER = logging.getLogger(__name__)
READ_RETRY_DELAYS = (1, 2, 4)
READ_RETRY_TIMEOUT = 45


class PeplinkError(Exception):
    """A router operation failed; messages never contain credential-bearing URLs."""


class TransientError(PeplinkError):
    """A temporary transport or incomplete read failure that can be retried safely."""


class AuthenticationError(PeplinkError):
    """The supplied credentials or token were rejected."""


class PendingChangesError(PeplinkError):
    """Router changes are pending and cannot be applied safely by this operation."""


@dataclass(frozen=True)
class Snapshot:
    config: dict[str, Any]
    active: bool
    pending: bool


def normalize_url(value: str) -> str:
    """Require a router base URL, excluding embedded credentials or tokens."""
    value = value.strip().rstrip("/")
    u = urlsplit(value)
    if (
        u.scheme not in {"http", "https"}
        or not u.hostname
        or u.username
        or u.password
        or u.query
        or u.fragment
        or u.path
    ):
        raise ValueError("Enter the router base URL without a path, query, or credentials.")
    return value


class PeplinkClient:
    def __init__(
        self,
        session: ClientSession,
        router_url: str,
        mode: str,
        client_id: str,
        client_secret: str,
        *,
        verify_ssl: bool = True,
        token_url: str = IC2_TOKEN_URL,
    ) -> None:
        self.session = session
        self.router_url = normalize_url(router_url)
        if mode not in {MODE_DIRECT, MODE_IC2}:
            raise ValueError("Unknown connection mode.")
        self.mode = mode
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.token_url = token_url
        self._token = ""
        self._refresh_token = ""
        self._expires_at = 0.0
        self._auth_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()

    async def _http(self, method: str, url: str, **kwargs) -> str:
        try:
            async with self.session.request(
                method,
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=ClientTimeout(total=30),
                allow_redirects=False,
                ssl=self.verify_ssl if url.startswith(self.router_url + "/") else True,
                **kwargs,
            ) as response:
                if response.status in {401, 403}:
                    raise AuthenticationError("Authentication was rejected.")
                if response.status in {408, 429, 500, 502, 503, 504}:
                    raise TransientError(
                        f"Temporary router request failure (HTTP {response.status})."
                    )
                if response.status >= 300:
                    raise PeplinkError(f"Router request failed (HTTP {response.status}).")
                return await response.text()
        except ClientSSLError:
            raise PeplinkError("TLS verification failed; check the router certificate.") from None
        except ClientConnectionError, ClientPayloadError, TimeoutError:
            raise TransientError("Temporary connection failure or response timeout.") from None
        except ClientError:
            raise PeplinkError("Unable to communicate with the router or token service.") from None

    @staticmethod
    def _json(raw: str) -> dict[str, Any]:
        try:
            data = json.loads(raw)
        except ValueError:
            raise PeplinkError("Router returned an invalid JSON response.") from None
        if not isinstance(data, dict):
            raise PeplinkError("Router returned an unexpected response.")
        return data

    async def _oauth(self, grant: dict[str, str]) -> dict[str, Any]:
        result = self._json(
            await self._http(
                "POST",
                self.token_url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    **grant,
                },
            )
        )
        if result.get("error") or not result.get("access_token"):
            raise AuthenticationError("IC2 could not issue an access token.")
        return result

    async def _ensure_token(self) -> None:
        async with self._auth_lock:
            if self._token and time.monotonic() < self._expires_at:
                return
            if self.mode == MODE_IC2:
                result = None
                if self._refresh_token:
                    try:
                        result = await self._oauth(
                            {
                                "grant_type": "refresh_token",
                                "refresh_token": self._refresh_token,
                            }
                        )
                    except AuthenticationError, PeplinkError:
                        # A revoked/expired refresh token is recoverable with client credentials.
                        result = None
                if result is None:
                    result = await self._oauth({"grant_type": "client_credentials"})
                self._token = result["access_token"]
                self._refresh_token = result.get("refresh_token", self._refresh_token)
                lifetime = result.get("expires_in", 172800)
            else:
                result = self._json(
                    await self._http(
                        "POST",
                        self.router_url + "/api/auth.token.grant",
                        json={
                            "clientId": self.client_id,
                            "clientSecret": self.client_secret,
                        },
                    )
                )
                data = result.get("response", {})
                if result.get("stat") != "ok" or not data.get("accessToken"):
                    raise AuthenticationError("Router could not issue an access token.")
                self._token = data["accessToken"]
                lifetime = data.get("expiresIn", 172800)
            if not isinstance(self._token, str) or not isinstance(lifetime, (int, float)):
                self._token = ""
                raise PeplinkError("Token service returned an invalid token response.")
            self._expires_at = time.monotonic() + max(0, lifetime - min(60, lifetime / 10))

    async def _request(self, method: str, path: str, **kwargs) -> str:
        """Renew on expiry/auth rejection; retry only an explicit authentication failure."""
        params = dict(kwargs.pop("params", {}))
        for attempt in range(2):
            await self._ensure_token()
            used_token = self._token
            params["access_token" if self.mode == MODE_IC2 else "accessToken"] = used_token
            try:
                raw = await self._http(method, self.router_url + path, params=params, **kwargs)
                # Some firmware reports authentication errors in an HTTP 200 JSON response.
                if raw.lstrip().startswith("{"):
                    try:
                        body = self._json(raw)
                    except PeplinkError:
                        if method == "GET":
                            raise TransientError(
                                "Router returned an incomplete read response."
                            ) from None
                        raise
                    message = str(body.get("message", "")).lower()
                    if body.get("stat") == "fail" and any(
                        text in message
                        for text in ("unauthorized", "invalid token", "token expired")
                    ):
                        raise AuthenticationError("Router rejected the access token.")
                return raw
            except AuthenticationError:
                if attempt:
                    raise
                async with self._auth_lock:
                    if self._token == used_token:
                        self._expires_at = 0
        raise AuthenticationError("Authentication was rejected.")

    async def _read_with_retry(self, operation, description: str):
        """Keep the current HA state while safe reads recover, with a fixed deadline."""
        try:
            async with asyncio.timeout(READ_RETRY_TIMEOUT):
                for attempt in range(len(READ_RETRY_DELAYS) + 1):
                    try:
                        return await operation()
                    except TransientError as exc:
                        if attempt == len(READ_RETRY_DELAYS):
                            raise
                        delay = READ_RETRY_DELAYS[attempt]
                        LOGGER.debug(
                            "Temporary %s failure (%s); retry %s in %s seconds",
                            description,
                            str(exc),
                            attempt + 1,
                            delay,
                        )
                        await asyncio.sleep(delay)
        except TimeoutError:
            raise TransientError("Router read did not recover before the retry deadline.") from None

    async def _api(self, method: str, function: str, **kwargs) -> dict[str, Any]:
        async def request():
            raw = await self._request(method, "/api/" + function, **kwargs)
            try:
                result = self._json(raw)
            except PeplinkError:
                if method == "GET":
                    raise TransientError(
                        "Router returned an incomplete JSON read response."
                    ) from None
                raise
            if result.get("stat") != "ok":
                raise PeplinkError("Router API reported that the operation failed.")
            return result

        if method == "GET":
            return await self._read_with_retry(request, "firewall read")
        return await request()

    async def _activation(self) -> tuple[bool, bool]:
        async def request():
            raw = await self._request(
                "GET", "/cgi-bin/MANGA/chkactivate.cgi", params={"extended": "1"}
            )
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                raise TransientError("Router returned an incomplete application status.") from None
            status = root.findtext(".//status")
            modified = root.findtext(".//modified")
            if status is None or modified not in {"0", "1"}:
                raise TransientError("Router did not report application status.")
            return status == "Activated" and modified == "0", modified == "1"

        return await self._read_with_retry(request, "application status read")

    async def _read_snapshot(self) -> Snapshot:
        before = await self._activation()
        result = await self._api("GET", "config.firewall", params={"type": "outbound"})
        after = await self._activation()
        config = result.get("response")
        if not isinstance(config, dict):
            raise PeplinkError("Router did not return firewall configuration.")
        return Snapshot(config, before[0] and after[0], before[1] or after[1])

    async def read_snapshot(self) -> Snapshot:
        async with self._operation_lock:
            return await self._read_snapshot()

    async def set_group_enabled(self, tag: str, enabled: bool) -> Snapshot:
        """Save targeted edits, verify preservation, apply, and confirm active state."""
        async with self._operation_lock:
            snapshot = await self._read_snapshot()
            if not snapshot.active:
                raise PendingChangesError("Apply or discard existing router changes first.")
            rules = matching_rules(snapshot.config, tag)
            if not rules:
                raise RuleError("No outbound rules match this prefix.")
            # Validate every payload before the first write, including advanced settings.
            forms = [(rule, rule_form(rule, enabled)) for rule in rules if rule.enabled != enabled]
            if not forms:
                return snapshot
            expected = deepcopy(snapshot.config)
            try:
                for rule, form in forms:
                    raw = await self._request("POST", "/cgi-bin/MANGA/admin.cgi", data=form)
                    try:
                        response = ET.fromstring(raw)
                    except ET.ParseError:
                        raise PeplinkError("Router returned an invalid Save response.") from None
                    if response.findtext(".//status") != "1":
                        raise PeplinkError("Router rejected the firewall rule Save.")
                    expected["outbound"]["rule"][rule.id]["enable"] = enabled
                    actual = (
                        await self._api(
                            "GET",
                            "config.firewall",
                            params={"type": "outbound"},
                        )
                    ).get("response")
                    # Include all rules, defaults, and order before applying the saved edits.
                    if self._settings(actual) != self._settings(expected):
                        raise PeplinkError(
                            "Router settings changed unexpectedly; changes were not applied."
                        )
                await self._api("POST", "cmd.config.apply", json={})
                for _ in range(15):
                    verified = await self._read_snapshot()
                    if verified.active:
                        if self._settings(verified.config) != self._settings(expected):
                            raise PeplinkError(
                                "Applied firewall state differs from the requested state."
                            )
                        return verified
                    await asyncio.sleep(2)
                raise PeplinkError("Router did not confirm that changes were applied.")
            except PeplinkError, RuleError:
                # Do not discard the global pending configuration: another admin may have edited it.
                raise

    @staticmethod
    def _settings(config: dict | None) -> dict | None:
        """References describe live devices, rather than the firewall settings being changed."""
        if not isinstance(config, dict):
            return None
        return {key: value for key, value in config.items() if key != "reference"}
