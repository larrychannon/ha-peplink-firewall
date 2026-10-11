"""A switch enables every outbound rule with its exact generated prefix."""

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import PeplinkConfigEntry
from .const import CONF_GROUPS, CONF_ROUTER_URL, CONF_TAG, DOMAIN
from .coordinator import PeplinkCoordinator
from .rules import group_state, matching_rules


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PeplinkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities(
        [
            PeplinkFirewallSwitch(entry.runtime_data, entry, group)
            for group in entry.options.get(CONF_GROUPS, [])
        ]
    )


class PeplinkFirewallSwitch(CoordinatorEntity[PeplinkCoordinator], SwitchEntity):
    _attr_has_entity_name = True
    _attr_icon = "mdi:shield-lock"

    def __init__(
        self, coordinator: PeplinkCoordinator, entry: PeplinkConfigEntry, group: dict
    ) -> None:
        super().__init__(coordinator)
        self.tag = group[CONF_TAG]
        self._attr_name = group["name"]
        self._attr_unique_id = f"{entry.entry_id}_{self.tag}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            manufacturer="Peplink",
            name=entry.title,
            configuration_url=entry.data[CONF_ROUTER_URL],
        )

    @property
    def rules(self):
        return matching_rules(self.coordinator.data.config, self.tag)

    @property
    def available(self) -> bool:
        return super().available and bool(self.rules)

    @property
    def is_on(self) -> bool | None:
        if not self.coordinator.data.active:
            return None
        return group_state(self.rules)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {"rule_prefix": self.tag}
        rules = self.rules
        return {
            "rule_prefix": self.tag,
            "matched_rules": len(rules),
            "enabled_rules": sum(rule.enabled for rule in rules),
            "rule_names": [rule.name for rule in rules],
            "pending_changes": self.coordinator.data.pending,
            "configuration_active": self.coordinator.data.active,
        }

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.set_group_enabled(self.tag, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.set_group_enabled(self.tag, False)
