"""Shared polling for all tagged outbound switches on one router."""

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AuthenticationError, PeplinkClient, PeplinkError, Snapshot
from .const import CONF_INTERVAL, DEFAULT_INTERVAL, DOMAIN
from .rules import RuleError, outbound_rules

LOGGER = logging.getLogger(__name__)


class PeplinkCoordinator(DataUpdateCoordinator[Snapshot]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: PeplinkClient) -> None:
        super().__init__(
            hass,
            LOGGER,
            name=DOMAIN,
            config_entry=entry,
            update_interval=timedelta(seconds=entry.options.get(CONF_INTERVAL, DEFAULT_INTERVAL)),
            always_update=False,
        )
        self.client = client

    async def _async_update_data(self) -> Snapshot:
        try:
            result = await self.client.read_snapshot()
            outbound_rules(result.config)
            return result
        except AuthenticationError as exc:
            raise ConfigEntryAuthFailed(str(exc)) from exc
        except (PeplinkError, RuleError) as exc:
            raise UpdateFailed(str(exc)) from exc

    async def set_group_enabled(self, tag: str, enabled: bool) -> None:
        try:
            snapshot = await self.client.set_group_enabled(tag, enabled)
        except (PeplinkError, RuleError) as exc:
            # A partial Save or failed Apply must immediately invalidate the old state.
            self.async_set_update_error(UpdateFailed(str(exc)))
            await self.async_request_refresh()
            if isinstance(exc, AuthenticationError):
                self.config_entry.async_start_reauth(self.hass)
            raise HomeAssistantError(str(exc)) from exc
        self.async_set_updated_data(snapshot)
