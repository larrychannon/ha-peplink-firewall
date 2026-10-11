"""Token expiry and outbound-only save/apply/readback behavior over real mock HTTP."""

import asyncio
from copy import deepcopy

import pytest
from aiohttp import ClientSession

from custom_components.peplink_firewall.api import (
    PendingChangesError,
    PeplinkClient,
    PeplinkError,
    normalize_url,
)
from custom_components.peplink_firewall.rules import (
    OutboundRule,
    RuleError,
    group_state,
    matching_rules,
    rule_form,
)

TAG = "[HA-A7K2]"


def client(session, router, mode="ic2"):
    return PeplinkClient(
        session,
        router.url,
        mode,
        "dummy-client",
        "dummy-secret",
        token_url=router.url + "/oauth",
    )


def test_prefix_and_order(config):
    before = deepcopy(config)
    rules = matching_rules(config, TAG)
    assert {rule.id for rule in rules} == {"9", "10"}
    assert group_state(rules) is None
    config["outbound"]["rule"]["order"].reverse()
    assert {rule.id for rule in matching_rules(config, TAG)} == {"9", "10"}
    assert all(rule.id != "13" for rule in rules)
    assert before["outbound"]["rule"]["9"] == config["outbound"]["rule"]["9"]


def test_form_changes_only_enable(config):
    rule = OutboundRule("9", config["outbound"]["rule"]["9"])
    enabled = rule_form(rule, True)
    disabled = rule_form(rule, False)
    assert enabled.pop("enable") == "yes"
    assert enabled == disabled
    assert disabled["rulename"] == TAG + " iPad Pro"
    assert disabled["direction"] == "o"
    assert disabled["srciptype"] == "mac" and disabled["dstiptype"] == "any"
    assert "new_order" not in disabled


def test_network_ports_schedule_and_logging_are_preserved(config):
    settings = deepcopy(config["outbound"]["rule"]["9"])
    settings.update({"schedule": 7, "logging": True, "conn_id": 2})
    settings["protocol"] = {"type": "tcp"}
    settings["source"] = {
        "type": "network",
        "network": {"ip": "192.0.2.0", "mask": 24},
        "port": [1000, 2000],
    }
    settings["destination"] = {"type": "domain", "domain": "example.test", "port": [443]}
    before = deepcopy(settings)
    form = rule_form(OutboundRule("9", settings), False)
    assert form["protocol"] == "TCP" and form["sche_profile"] == "7"
    assert form["connid"] == "2" and form["eventlog"] == "yes"
    assert (form["srciptype"], form["srcip"], form["srcmask"]) == ("network", "192.0.2.0", "24")
    assert (form["srcport_type"], form["srcport"], form["srcportlast"]) == ("2", "1000", "2000")
    assert (form["dstiptype"], form["dstdomain"], form["dstport"]) == (
        "domain",
        "example.test",
        "443",
    )
    assert settings == before


async def test_no_op_does_not_save_or_apply(router):
    router.config["outbound"]["rule"]["10"]["enable"] = True
    async with ClientSession() as session:
        assert (await client(session, router).set_group_enabled(TAG, True)).active
        assert not router.saves and router.applies == 0


@pytest.mark.parametrize(
    "url",
    [
        "https://host/api",
        "https://host?access_token=secret",
        "https://user:secret@host",
        "file:///tmp",
    ],
)
def test_url_rejects_credential_or_path_injection(url):
    with pytest.raises(ValueError):
        normalize_url(url)


@pytest.mark.parametrize("mode", ["ic2", "direct"])
async def test_auth_modes_and_concurrent_renewal(router, mode):
    async with ClientSession() as session:
        api = client(session, router, mode)
        result = await api.read_snapshot()
        assert result.active
        assert len(router.grants) == 1
        expected_key = "access_token" if mode == "ic2" else "accessToken"
        assert all(
            expected_key in query
            for _, path, query in router.requests
            if path.endswith("config.firewall")
        )
        if mode == "direct":
            assert router.grants[0] == {"clientId": "dummy-client", "clientSecret": "dummy-secret"}
        api._expires_at = 0
        await asyncio.gather(*(api._request("GET", "/api/config.firewall") for _ in range(4)))
        assert len(router.grants) == 2
        if mode == "ic2":
            assert router.grants[-1]["grant_type"] == "refresh_token"


async def test_refresh_falls_back_to_client_credentials(router):
    async with ClientSession() as session:
        api = client(session, router)
        await api.read_snapshot()
        api._expires_at = 0
        router.refresh_rejected = True
        await api.read_snapshot()
        assert [grant["grant_type"] for grant in router.grants] == [
            "client_credentials",
            "refresh_token",
            "client_credentials",
        ]


async def test_rejected_token_is_renewed_and_query_preserved(router):
    async with ClientSession() as session:
        api = client(session, router)
        await api.read_snapshot()
        router.reject_once = True
        result = await api.read_snapshot()
        assert result.active and len(router.grants) == 2
        assert all(
            query["type"] == "outbound"
            for _, path, query in router.requests
            if path.endswith("config.firewall")
        )


@pytest.mark.parametrize("enabled", [True, False])
async def test_group_save_apply_preserves_other_settings(router, config, enabled):
    async with ClientSession() as session:
        api = client(session, router)
        result = await api.set_group_enabled(TAG, enabled)
        assert result.active and not result.pending
        expected = deepcopy(config)
        for key in ["9", "10"]:
            expected["outbound"]["rule"][key]["enable"] = enabled
        assert api._settings(result.config) == api._settings(expected)
        assert router.applies == 1
        assert len(router.saves) == 1
        assert router.saves[0]["ruleid"] == ("10" if enabled else "9")


async def test_pending_external_edits_block_all_writes(router):
    router.pending = True
    async with ClientSession() as session:
        api = client(session, router)
        assert not (await api.read_snapshot()).active
        with pytest.raises(PendingChangesError):
            await api.set_group_enabled(TAG, False)
        assert not router.saves and router.applies == 0


async def test_unknown_settings_validated_before_any_write(router):
    router.config["outbound"]["rule"]["10"]["enable"] = True
    router.config["outbound"]["rule"]["10"]["future_setting"] = "preserve-me"
    async with ClientSession() as session:
        with pytest.raises(RuleError):
            await client(session, router).set_group_enabled(TAG, False)
        assert not router.saves and router.applies == 0


async def test_failed_save_is_never_applied(router):
    router.save_rejected = True
    async with ClientSession() as session:
        with pytest.raises(PeplinkError, match="rejected"):
            await client(session, router).set_group_enabled(TAG, False)
        assert router.applies == 0


async def test_unrelated_mutation_is_never_applied(router):
    router.tamper = True
    async with ClientSession() as session:
        api = client(session, router)
        with pytest.raises(PeplinkError, match="unexpectedly"):
            await api.set_group_enabled(TAG, False)
        assert router.applies == 0
        snapshot = await api.read_snapshot()
        assert snapshot.pending and not snapshot.active


async def test_failed_apply_is_not_reported_as_active(router):
    router.apply_rejected = True
    async with ClientSession() as session:
        api = client(session, router)
        with pytest.raises(PeplinkError):
            await api.set_group_enabled(TAG, False)
        assert not (await api.read_snapshot()).active


async def test_missing_tag_never_writes(router):
    async with ClientSession() as session:
        with pytest.raises(RuleError, match="No outbound"):
            await client(session, router).set_group_enabled("[HA-Z9Y8]", False)
        assert not router.saves and router.applies == 0
