#!/usr/bin/env python3
"""Generate an InControl 2 access token using development credentials."""

import argparse
import json
import os
from pathlib import Path
import shlex
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

TOKEN_URL = "https://api.ic.peplink.com/api/oauth2/token"


def load_env(path: Path) -> dict[str, str]:
    """Read simple KEY=value assignments without executing shell commands."""
    values = {}
    if not path.exists():
        return values
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.removeprefix("export ").partition("=")
        if not separator:
            raise ValueError(f"Invalid .env assignment on line {number}.")
        try:
            parts = shlex.split(value, comments=True)
        except ValueError:
            raise ValueError(f"Invalid .env quoting on line {number}.") from None
        if len(parts) > 1:
            raise ValueError(f"Quote the .env value on line {number}.")
        values[key.strip()] = parts[0] if parts else ""
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file", type=Path,
        default=Path(__file__).resolve().with_name(".env"),
        help="Credentials file (default: .env beside this script).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print the full token response, including expiry and refresh token.",
    )
    args = parser.parse_args()
    try:
        credentials = load_env(args.env_file)
        credentials.update(os.environ)
        client_id = credentials.get("IC2_CLIENT_ID") or credentials.get("IC2_CLIENT")
        client_secret = credentials.get("IC2_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise ValueError("Set IC2_CLIENT_ID and IC2_CLIENT_SECRET in .env or the environment.")
        payload = urlencode({
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        }).encode()
        request = Request(TOKEN_URL, data=payload, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "Peplink-HomeAssistant-Dev/0.1",
        })
        with urlopen(request, timeout=30) as response:
            result = json.load(response)
        if not isinstance(result, dict) or not isinstance(result.get("access_token"), str) or not result["access_token"]:
            raise ValueError("IC2 returned no usable access_token.")
    except HTTPError as exc:
        print(f"IC2 token request failed (HTTP {exc.code}).", file=sys.stderr)
        return 1
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(f"Token generation failed: {message}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.json else result["access_token"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
