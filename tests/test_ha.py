"""HA 2026.10 config/options flow and truthful switch-state tests."""

from copy import deepcopy
from unittest.mock import AsyncMock, patch

from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.peplink_firewall.api import AuthenticationError, Snapshot
from custom_components.peplink_firewall.const import DOMAIN
from custom_components.peplink_firewall.coordinator import PeplinkCoordinator
from custom_components.peplink_firewall.switch import PeplinkFirewallSwitch

TAG = "[HA-A7K2]"
CONNECTION = {
    "connection_mode": "ic2",
    "router_url": "https://router.example.test",
    "client_id": "dummy-client",
    "client_secret": "dummy-secret",
    "verify_ssl": True,
}


async def test_setup_generates_tag_and_can_reuse_existing_prefix(hass, config):
    fake = AsyncMock()
    fake.read_snapshot.return_value = Snapshot(config, True, False)
    with (
        patch("custom_components.peplink_firewall.config_flow.make_client", return_value=fake),
        patch("custom_components.peplink_firewall.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        assert result["type"] == FlowResultType.FORM
        result = await hass.config_entries.flow.async_configure(result["flow_id"], CONNECTION)
        assert result["step_id"] == "group"
        defaults = {str(key): key.default() for key in result["data_schema"].schema}
        assert defaults["tag"].startswith("[HA-") and len(defaults["tag"]) == 9
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "group_name": "iPad internet block",
                "tag": TAG,
            },
        )
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert result["data"]["client_secret"] == CONNECTION["client_secret"]
        assert "access_token" not in result["data"]
        assert result["options"]["groups"] == [{"name": "iPad internet block", "tag": TAG}]
        await hass.async_block_till_done()


async def test_bad_credentials_and_bad_prefix_are_visible_errors(hass, config):
    fake = AsyncMock()
    fake.read_snapshot.side_effect = AuthenticationError("Rejected")
    with patch("custom_components.peplink_firewall.config_flow.make_client", return_value=fake):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        result = await hass.config_entries.flow.async_configure(result["flow_id"], CONNECTION)
        assert result["errors"] == {"base": "invalid_auth"}
        fake.read_snapshot.side_effect = None
        fake.read_snapshot.return_value = Snapshot(config, True, False)
        result = await hass.config_entries.flow.async_configure(result["flow_id"], CONNECTION)
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "group_name": "Block",
                "tag": "[HA-A7K2X]",
            },
        )
        assert result["errors"] == {"tag": "invalid_tag"}


async def test_options_add_group_and_reject_duplicate(hass):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=CONNECTION,
        unique_id=CONNECTION["router_url"],
        options={"groups": [{"name": "iPad", "tag": TAG}], "poll_interval": 30},
    )
    entry.add_to_hass(hass)
    with patch.object(hass.config_entries, "async_reload", return_value=True):
        result = await hass.config_entries.options.async_init(entry.entry_id)
        assert result["type"] == FlowResultType.MENU
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], {"next_step_id": "add_group"}
        )
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], {"group_name": "Duplicate", "tag": TAG}
        )
        assert result["errors"] == {"tag": "duplicate_tag"}
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], {"group_name": "TV", "tag": "[HA-Z9Y8]"}
        )
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert entry.options["groups"] == [
            {"name": "iPad", "tag": TAG},
            {"name": "TV", "tag": "[HA-Z9Y8]"},
        ]
        assert entry.data == CONNECTION
        await hass.async_block_till_done()


async def test_reauthentication_updates_credentials(hass, config):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=CONNECTION,
        unique_id=CONNECTION["router_url"],
        options={},
    )
    entry.add_to_hass(hass)
    fake = AsyncMock()
    fake.read_snapshot.return_value = Snapshot(config, True, False)
    with (
        patch("custom_components.peplink_firewall.config_flow.make_client", return_value=fake),
        patch.object(hass.config_entries, "async_reload", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "reauth", "entry_id": entry.entry_id},
            data=CONNECTION,
        )
        assert result["step_id"] == "reauth_confirm"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                **CONNECTION,
                "client_secret": "updated-secret",
            },
        )
        assert result["type"] == FlowResultType.ABORT
        assert result["reason"] == "reauth_successful"
        assert entry.data["client_secret"] == "updated-secret"
        await hass.async_block_till_done()


async def test_switch_mixed_pending_unavailable_and_external_changes(hass, config):
    entry = MockConfigEntry(domain=DOMAIN, data=CONNECTION, options={})
    entry.add_to_hass(hass)
    coordinator = PeplinkCoordinator(hass, entry, AsyncMock())
    coordinator.data = Snapshot(deepcopy(config), True, False)
    entity = PeplinkFirewallSwitch(coordinator, entry, {"tag": TAG, "name": "iPad"})
    assert entity.available and entity.is_on is None  # Mixed enable states.
    assert entity.extra_state_attributes["enabled_rules"] == 1
    coordinator.data.config["outbound"]["rule"]["10"]["enable"] = True
    assert entity.is_on is True  # A change made outside Home Assistant is reflected.
    coordinator.data = Snapshot(coordinator.data.config, False, True)
    assert entity.available and entity.is_on is None  # Saved config is not active yet.
    coordinator.data.config["outbound"]["rule"]["9"]["name"] = "Tag removed"
    coordinator.data.config["outbound"]["rule"]["10"]["name"] = "Tag removed too"
    assert not entity.available
    coordinator.last_update_success = False
    assert not entity.available
    assert "client_secret" not in entity.extra_state_attributes


async def test_real_ha_entry_and_switch_service_with_simulated_router(hass, router):
    """Load the actual integration and use HA's switch service against mock HTTP."""
    from aiohttp import ClientSession

    from custom_components.peplink_firewall.api import PeplinkClient

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={**CONNECTION, "router_url": router.url},
        options={"groups": [{"name": "iPad block", "tag": TAG}], "poll_interval": 30},
        unique_id=router.url,
    )
    entry.add_to_hass(hass)
    async with ClientSession() as session:
        api = PeplinkClient(
            session, router.url, "ic2", "dummy", "dummy", token_url=router.url + "/oauth"
        )
        with patch("custom_components.peplink_firewall.make_client", return_value=api):
            assert await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()
            states = [state for state in hass.states.async_all() if state.domain == "switch"]
            assert len(states) == 1 and states[0].state == "unknown"
            entity_id = states[0].entity_id
            await hass.services.async_call(
                "switch", "turn_off", {"entity_id": entity_id}, blocking=True
            )
            await hass.async_block_till_done()
            assert hass.states.get(entity_id).state == "off"
            assert router.applies == 1
            assert router.config["inbound"]["rule"]["13"]["enable"] is True
            for rule_id in ["9", "10"]:
                router.config["outbound"]["rule"][rule_id]["enable"] = True
            await entry.runtime_data.async_refresh()
            await hass.async_block_till_done()
            assert hass.states.get(entity_id).state == "on"
            assert await hass.config_entries.async_unload(entry.entry_id)
            await hass.async_block_till_done()


async def test_ha_service_apply_failure_leaves_unknown_state(hass, router):
    import pytest
    from aiohttp import ClientSession
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.peplink_firewall.api import PeplinkClient

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={**CONNECTION, "router_url": router.url},
        options={"groups": [{"name": "iPad block", "tag": TAG}]},
        unique_id=router.url,
    )
    entry.add_to_hass(hass)
    async with ClientSession() as session:
        api = PeplinkClient(
            session, router.url, "ic2", "dummy", "dummy", token_url=router.url + "/oauth"
        )
        with patch("custom_components.peplink_firewall.make_client", return_value=api):
            assert await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()
            entity_id = next(s.entity_id for s in hass.states.async_all() if s.domain == "switch")
            router.apply_rejected = True
            with pytest.raises(HomeAssistantError):
                await hass.services.async_call(
                    "switch", "turn_off", {"entity_id": entity_id}, blocking=True
                )
            await hass.async_block_till_done()
            state = hass.states.get(entity_id)
            assert state.state == "unknown"
            assert state.attributes["pending_changes"] is True
            assert await hass.config_entries.async_unload(entry.entry_id)
            await hass.async_block_till_done()


async def test_two_prefix_sets_and_transient_reads_keep_ha_available(hass, router):
    from aiohttp import ClientSession, web

    from custom_components.peplink_firewall.api import PeplinkClient

    second_tag = "[HA-Z9Y8]"
    router.config["outbound"]["rule"]["11"]["name"] = second_tag + " Guest"
    router.config["outbound"]["rule"]["10"]["enable"] = True
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={**CONNECTION, "router_url": router.url},
        options={
            "groups": [
                {"name": "Tablets", "tag": TAG},
                {"name": "Guests", "tag": second_tag},
            ]
        },
        unique_id=router.url,
    )
    entry.add_to_hass(hass)
    async with ClientSession() as session:
        api = PeplinkClient(
            session, router.url, "ic2", "dummy", "dummy", token_url=router.url + "/oauth"
        )
        with (
            patch("custom_components.peplink_firewall.make_client", return_value=api),
            patch("custom_components.peplink_firewall.api.READ_RETRY_DELAYS", (0, 0, 0)),
        ):
            assert await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()
            states = {
                s.attributes["rule_prefix"]: s
                for s in hass.states.async_all()
                if s.domain == "switch"
            }
            assert len(states) == 2
            assert states[TAG].state == states[second_tag].state == "on"
            observed = []
            unsubscribe = hass.bus.async_listen(
                "state_changed",
                lambda event: (
                    observed.append(event.data["new_state"].state)
                    if event.data.get("new_state") and event.data["entity_id"].startswith("switch.")
                    else None
                ),
            )
            try:
                router.faults["/api/config.firewall"] = [web.Response(status=503)]
                await entry.runtime_data.async_refresh()
                await hass.async_block_till_done()
                assert hass.states.get(states[TAG].entity_id).state == "on"
                # The router has accepted Apply, but its next status read is temporarily down.
                router.after_apply_faults = {
                    "/cgi-bin/MANGA/chkactivate.cgi": [web.Response(status=502)]
                }
                await hass.services.async_call(
                    "switch", "turn_off", {"entity_id": states[TAG].entity_id}, blocking=True
                )
                await hass.async_block_till_done()
                assert hass.states.get(states[TAG].entity_id).state == "off"
                assert hass.states.get(states[second_tag].entity_id).state == "on"
                assert router.applies == 1 and len(router.saves) == 2
                assert "unavailable" not in observed
                router.faults["/api/config.firewall"] = [web.Response(status=503) for _ in range(4)]
                await entry.runtime_data.async_refresh()
                await hass.async_block_till_done()
                assert hass.states.get(states[TAG].entity_id).state == "unavailable"
                await entry.runtime_data.async_refresh()
                await hass.async_block_till_done()
                assert hass.states.get(states[TAG].entity_id).state == "off"
            finally:
                unsubscribe()
                assert await hass.config_entries.async_unload(entry.entry_id)
                await hass.async_block_till_done()
