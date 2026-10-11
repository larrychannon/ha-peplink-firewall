"""Match outbound rules and preserve their settings when serializing edits."""

import re
import secrets
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

TAG_PATTERN = re.compile(r"\[HA-[A-Z0-9]{4}\]")


class RuleError(Exception):
    """A rule cannot be changed safely."""


def new_tag(existing: set[str] | None = None) -> str:
    """Generate a short, persistent group tag without an existing collision."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        tag = "[HA-" + "".join(secrets.choice(alphabet) for _ in range(4)) + "]"
        if tag not in (existing or set()):
            return tag


def valid_tag(tag: str) -> bool:
    return TAG_PATTERN.fullmatch(tag) is not None


@dataclass(frozen=True)
class OutboundRule:
    """One outbound rule, identified by its current router ID."""

    id: str
    config: dict[str, Any]

    @property
    def name(self) -> str:
        return self.config["name"]

    @property
    def enabled(self) -> bool:
        return self.config["enable"]


def outbound_rules(config: dict[str, Any]) -> list[OutboundRule]:
    """Read only outbound rules; the router's order is never used for association."""
    rules = config.get("outbound", {}).get("rule")
    if not isinstance(rules, dict):
        raise RuleError("Router response does not contain outbound firewall rules.")
    result = []
    for key, value in rules.items():
        if key == "order" or str(key) == "0":
            continue
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            raise RuleError("Router returned an invalid outbound rule.")
        if not isinstance(value.get("enable"), bool):
            raise RuleError("Router did not report a rule's enabled state.")
        result.append(OutboundRule(str(key), deepcopy(value)))
    return result


def matching_rules(config: dict[str, Any], tag: str) -> list[OutboundRule]:
    if not valid_tag(tag):
        raise RuleError("Invalid HA rule prefix.")
    return [rule for rule in outbound_rules(config) if rule.name.startswith(tag)]


def group_state(rules: list[OutboundRule]) -> bool | None:
    states = {rule.enabled for rule in rules}
    return states.pop() if len(states) == 1 else None


def _known_fields(data: dict, known: set[str], context: str) -> None:
    if set(data) - known:
        raise RuleError(f"Unsupported {context} settings; rule was not changed.")


def rule_form(rule: OutboundRule, enabled: bool) -> dict[str, str]:
    """Reject incomplete settings before any edit is submitted."""
    try:
        form = _rule_form(rule, enabled)
        if any(not isinstance(value, str) for value in form.values()):
            raise RuleError("Unsupported field value; rule was not changed.")
        return form
    except KeyError, TypeError, AttributeError, ValueError:
        raise RuleError("Incomplete rule settings; rule was not changed.") from None


def _rule_form(rule: OutboundRule, enabled: bool) -> dict[str, str]:
    """Serialize the observed Web Admin form; never submit order or default policy."""
    c = rule.config
    _known_fields(
        c,
        {
            "name",
            "enable",
            "policy",
            "protocol",
            "source",
            "destination",
            "logging",
            "schedule",
            "conn_id",
            "incontrolManaged",
            "id",
        },
        "rule",
    )
    if c.get("incontrolManaged"):
        raise RuleError("This rule is managed by InControl; it was not changed.")
    policy = {"deny": "drop", "allow": "accept", "drop": "drop", "accept": "accept"}
    if c.get("policy") not in policy:
        raise RuleError("Unsupported rule action; rule was not changed.")
    form = {
        "section": "FIREWALL_modify",
        "direction": "o",
        "ruleid": rule.id,
        "rulename": rule.name,
        "sche_profile": str(c.get("schedule") or 0),
        "connid": str(c.get("conn_id") or "any"),
        "policy": policy[c["policy"]],
        "icmpid": "",
        "protocolid": "",
        "dpi": "",
        "webcategory": "",
        "dscp": "0",
    }
    if enabled:
        form["enable"] = "yes"
    if c.get("logging"):
        form["eventlog"] = "yes"
    protocol = c.get("protocol", {})
    _known_fields(protocol, {"type", "number", "icmp", "dscp"}, "protocol")
    kind = protocol.get("type", "any").lower()
    if kind not in {"any", "tcp", "udp", "icmp", "ip", "dscp"}:
        raise RuleError("Unsupported protocol; rule was not changed.")
    form["protocol"] = "ANY" if kind == "any" else kind.upper()
    if kind == "ip":
        form["protocolid"] = str(protocol["number"])
    elif kind == "icmp":
        icmp = protocol.get("icmp", {})
        _known_fields(icmp, {"type"}, "ICMP")
        form["icmpid"] = str(icmp.get("type", ""))
    elif kind == "dscp":
        form["dscp"] = str(protocol["dscp"])
    for prefix, endpoint in (("src", c.get("source", {})), ("dst", c.get("destination", {}))):
        _known_fields(
            endpoint,
            {
                "type",
                "ip",
                "network",
                "mac",
                "domain",
                "group",
                "client",
                "port",
            },
            "address",
        )
        address_type = endpoint.get("type", "any")
        if address_type not in {"any", "ip", "network", "mac", "domain", "group", "client"}:
            raise RuleError("Unsupported address type; rule was not changed.")
        form.update(
            {
                prefix + "iptype": address_type,
                prefix + "ip": endpoint.get("ip", ""),
                prefix + "mask": "24",
                prefix + "mac": endpoint.get("mac", ""),
                prefix + "domain": endpoint.get("domain", ""),
                prefix + "ethertype": "",
                prefix + "group": str(endpoint.get("group", 1)),
                prefix + "ssid": "",
                prefix + "port_type": "0",
                prefix + "port": "",
                prefix + "portlast": "",
                prefix + "port_map": "",
                prefix + "port_map_last": "",
            }
        )
        if prefix == "src":
            form["srcclient"] = str(endpoint.get("client", 0))
        if address_type == "network":
            network = endpoint.get("network", {})
            _known_fields(network, {"ip", "mask"}, "network")
            form[prefix + "ip"] = network["ip"]
            form[prefix + "mask"] = str(network["mask"])
        ports = endpoint.get("port", [])
        if ports == "any":
            ports = []
        if not isinstance(ports, list) or len(ports) > 2:
            raise RuleError("Unsupported port settings; rule was not changed.")
        if ports:
            if kind not in {"tcp", "udp"}:
                raise RuleError("Unexpected port settings; rule was not changed.")
            form[prefix + "port_type"] = str(len(ports))
            form[prefix + "port"] = str(ports[0])
            if len(ports) == 2:
                form[prefix + "portlast"] = str(ports[1])
    return form
