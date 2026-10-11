"""Home Assistant integration for tagged Peplink outbound firewall rules."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import PeplinkClient
from .const import (
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_MODE,
    CONF_ROUTER_URL,
)
from .coordinator import PeplinkCoordinator

type PeplinkConfigEntry = ConfigEntry[PeplinkCoordinator]
PLATFORMS = [Platform.SWITCH]


def make_client(hass: HomeAssistant, data: dict) -> PeplinkClient:
    return PeplinkClient(
        async_get_clientsession(hass),
        data[CONF_ROUTER_URL],
        data[CONF_MODE],
        data[CONF_CLIENT_ID],
        data[CONF_CLIENT_SECRET],
        verify_ssl=data.get("verify_ssl", True),
    )


async def async_setup_entry(hass: HomeAssistant, entry: PeplinkConfigEntry) -> bool:
    coordinator = PeplinkCoordinator(hass, entry, make_client(hass, entry.data))
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: PeplinkConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
