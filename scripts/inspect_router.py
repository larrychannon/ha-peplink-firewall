"""Read a tagged outbound group's state without changing router settings."""

import argparse
import asyncio
import json
import os
from pathlib import Path

from aiohttp import ClientSession

from custom_components.peplink_firewall.api import PeplinkClient, PeplinkError
from custom_components.peplink_firewall.rules import RuleError, group_state, matching_rules
from generate_ic2_token import load_env


async def inspect(args) -> None:
    values = load_env(args.env_file)
    values.update(os.environ)
    if args.mode == "ic2":
        client_id = values.get("IC2_CLIENT_ID") or values.get("IC2_CLIENT")
        secret = values.get("IC2_CLIENT_SECRET")
    else:
        client_id = values.get("ROUTER_CLIENT_ID")
        secret = values.get("ROUTER_CLIENT_SECRET")
    if not values.get("ROUTER_URL") or not client_id or not secret:
        raise ValueError("Set ROUTER_URL and the client credentials for the selected mode.")
    async with ClientSession() as session:
        api = PeplinkClient(session, values["ROUTER_URL"], args.mode, client_id, secret)
        snapshot = await api.read_snapshot()
        rules = matching_rules(snapshot.config, args.tag)
        state = group_state(rules) if snapshot.active else None
        print(
            json.dumps(
                {
                    "prefix": args.tag,
                    "state": "unavailable"
                    if not rules
                    else "unknown"
                    if state is None
                    else "on"
                    if state
                    else "off",
                    "configuration_active": snapshot.active,
                    "pending_changes": snapshot.pending,
                    "matched_rules": len(rules),
                    "enabled_rules": sum(rule.enabled for rule in rules),
                    "rule_names": [rule.name for rule in rules],
                },
                indent=2,
            )
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Exact prefix, such as [HA-A7K2].")
    parser.add_argument("--mode", choices=["ic2", "direct"], default="ic2")
    parser.add_argument(
        "--env-file", type=Path, default=Path(__file__).resolve().parents[1] / ".env"
    )
    args = parser.parse_args()
    try:
        asyncio.run(inspect(args))
    except (PeplinkError, RuleError, ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
