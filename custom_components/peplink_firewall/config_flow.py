"""UI setup, credential changes, and tagged switch management."""

from typing import Any

import probatio as p
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.core import callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from . import make_client
from .api import AuthenticationError, PeplinkError, normalize_url
from .const import (
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_GROUP_NAME,
    CONF_GROUPS,
    CONF_INTERVAL,
    CONF_MODE,
    CONF_ROUTER_URL,
    CONF_TAG,
    DEFAULT_INTERVAL,
    DOMAIN,
    MODE_DIRECT,
    MODE_IC2,
)
from .rules import RuleError, new_tag, outbound_rules, valid_tag


def connection_schema(existing: dict | None = None) -> p.Schema:
    values = existing or {}
    secret_key = p.Optional(CONF_CLIENT_SECRET) if existing else p.Required(CONF_CLIENT_SECRET)
    return p.Schema(
        {
            p.Required(CONF_MODE, default=values.get(CONF_MODE, MODE_IC2)): SelectSelector(
                SelectSelectorConfig(
                    options=[
                        SelectOptionDict(value=MODE_DIRECT, label="Direct router API"),
                        SelectOptionDict(value=MODE_IC2, label="InControl 2 Remote Web Admin"),
                    ]
                ),
            ),
            p.Required(CONF_ROUTER_URL, default=values.get(CONF_ROUTER_URL, "")): TextSelector(
                TextSelectorConfig(type=TextSelectorType.URL),
            ),
            p.Required(CONF_CLIENT_ID, default=values.get(CONF_CLIENT_ID, "")): str,
            secret_key: TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
            p.Required("verify_ssl", default=values.get("verify_ssl", True)): bool,
        }
    )


def group_schema(tag: str) -> p.Schema:
    return p.Schema(
        {
            p.Required(CONF_GROUP_NAME, default="Outbound firewall"): str,
            p.Required(CONF_TAG, default=tag): str,
        }
    )


class PeplinkFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._connection: dict[str, Any] = {}
        self._tag = new_tag()

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlowWithReload:
        return PeplinkOptionsFlow()

    async def _connection_step(self, step: str, user_input: dict | None) -> ConfigFlowResult:
        existing = None
        if step == "reconfigure":
            existing = self._get_reconfigure_entry().data
        elif step == "reauth_confirm":
            existing = self._get_reauth_entry().data
        errors = {}
        if user_input is not None:
            data = {**(existing or {}), **user_input}
            if not data.get(CONF_CLIENT_SECRET):
                data[CONF_CLIENT_SECRET] = (existing or {}).get(CONF_CLIENT_SECRET, "")
            try:
                data[CONF_ROUTER_URL] = normalize_url(data[CONF_ROUTER_URL])
                if not data[CONF_CLIENT_ID].strip() or not data[CONF_CLIENT_SECRET]:
                    raise AuthenticationError("Client credentials are required.")
                data[CONF_CLIENT_ID] = data[CONF_CLIENT_ID].strip()
                snapshot = await make_client(self.hass, data).read_snapshot()
                outbound_rules(snapshot.config)
                await self.async_set_unique_id(data[CONF_ROUTER_URL])
                if step == "user":
                    self._abort_if_unique_id_configured()
                    self._connection = data
                    return await self.async_step_group()
                entry = (
                    self._get_reconfigure_entry()
                    if step == "reconfigure"
                    else self._get_reauth_entry()
                )
                if data[CONF_ROUTER_URL] != entry.unique_id:
                    self._abort_if_unique_id_configured()
                self.hass.config_entries.async_update_entry(entry, unique_id=data[CONF_ROUTER_URL])
                return self.async_update_reload_and_abort(entry, data_updates=data)
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except PeplinkError, RuleError:
                errors["base"] = "cannot_connect"
            except ValueError:
                errors[CONF_ROUTER_URL] = "invalid_url"
        return self.async_show_form(
            step_id=step,
            data_schema=connection_schema(existing),
            errors=errors,
        )

    async def async_step_user(self, user_input: dict | None = None) -> ConfigFlowResult:
        return await self._connection_step("user", user_input)

    async def async_step_reconfigure(self, user_input: dict | None = None) -> ConfigFlowResult:
        return await self._connection_step("reconfigure", user_input)

    async def async_step_reauth(self, entry_data: dict) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict | None = None) -> ConfigFlowResult:
        return await self._connection_step("reauth_confirm", user_input)

    async def async_step_group(self, user_input: dict | None = None) -> ConfigFlowResult:
        errors = {}
        if user_input is not None:
            tag = user_input[CONF_TAG].strip()
            if not valid_tag(tag):
                errors[CONF_TAG] = "invalid_tag"
            elif not user_input[CONF_GROUP_NAME].strip():
                errors[CONF_GROUP_NAME] = "empty_name"
            else:
                return self.async_create_entry(
                    title=url_title(self._connection[CONF_ROUTER_URL]),
                    data=self._connection,
                    options={
                        CONF_INTERVAL: DEFAULT_INTERVAL,
                        CONF_GROUPS: [
                            {
                                "name": user_input[CONF_GROUP_NAME].strip(),
                                CONF_TAG: tag,
                            }
                        ],
                    },
                )
        return self.async_show_form(
            step_id="group", data_schema=group_schema(self._tag), errors=errors
        )


def url_title(url: str) -> str:
    return "Peplink " + url.split("://", 1)[1]


class PeplinkOptionsFlow(OptionsFlowWithReload):
    def __init__(self) -> None:
        self._tag = ""

    async def async_step_init(self, user_input: dict | None = None) -> ConfigFlowResult:
        return self.async_show_menu(
            step_id="init", menu_options=["add_group", "remove_group", "polling"]
        )

    async def async_step_add_group(self, user_input: dict | None = None) -> ConfigFlowResult:
        options = dict(self.config_entry.options)
        groups = list(options.get(CONF_GROUPS, []))
        existing = {group[CONF_TAG] for group in groups}
        if not self._tag:
            self._tag = new_tag(existing)
        errors = {}
        if user_input is not None:
            tag = user_input[CONF_TAG].strip()
            if not valid_tag(tag):
                errors[CONF_TAG] = "invalid_tag"
            elif tag in existing:
                errors[CONF_TAG] = "duplicate_tag"
            elif not user_input[CONF_GROUP_NAME].strip():
                errors[CONF_GROUP_NAME] = "empty_name"
            else:
                groups.append({"name": user_input[CONF_GROUP_NAME].strip(), CONF_TAG: tag})
                return self.async_create_entry(data={**options, CONF_GROUPS: groups})
        return self.async_show_form(
            step_id="add_group", data_schema=group_schema(self._tag), errors=errors
        )

    async def async_step_remove_group(self, user_input: dict | None = None) -> ConfigFlowResult:
        options = dict(self.config_entry.options)
        groups = options.get(CONF_GROUPS, [])
        if not groups:
            return self.async_abort(reason="no_groups")
        if user_input is not None:
            tag = user_input[CONF_TAG]
            registry = er.async_get(self.hass)
            entity_id = registry.async_get_entity_id(
                "switch", DOMAIN, f"{self.config_entry.entry_id}_{tag}"
            )
            if entity_id:
                registry.async_remove(entity_id)
            return self.async_create_entry(
                data={
                    **options,
                    CONF_GROUPS: [group for group in groups if group[CONF_TAG] != tag],
                }
            )
        return self.async_show_form(
            step_id="remove_group",
            data_schema=p.Schema(
                {
                    p.Required(CONF_TAG): p.In(
                        {
                            group[CONF_TAG]: f"{group['name']} — {group[CONF_TAG]}"
                            for group in groups
                        }
                    ),
                }
            ),
        )

    async def async_step_polling(self, user_input: dict | None = None) -> ConfigFlowResult:
        options = dict(self.config_entry.options)
        if user_input is not None:
            return self.async_create_entry(data={**options, **user_input})
        return self.async_show_form(
            step_id="polling",
            data_schema=p.Schema(
                {
                    p.Required(
                        CONF_INTERVAL, default=options.get(CONF_INTERVAL, DEFAULT_INTERVAL)
                    ): p.All(p.Coerce(int), p.Range(min=10, max=3600)),
                }
            ),
        )
