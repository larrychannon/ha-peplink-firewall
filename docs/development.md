# Developer reference

This document is for contributors working on the integration. These commands and
credential files are not part of installation or setup in Home Assistant.

## Authentication and state

- **Direct:** uses the router's API client ID/secret at `/api/auth.token.grant`
  and sends `accessToken`. It obtains another token before expiry or after an
  explicit authentication rejection.
- **IC2:** uses your IC2 OAuth client ID/secret at the IC2 token service and sends
  `access_token` to the Remote Web Admin URL. It refreshes before expiry and falls
  back to a client-credentials grant if the refresh token is rejected.
- Credentials are stored in standard HA config entries. Tokens stay in memory
  and are obtained again after restart. Credentials and tokens are excluded from
  entity attributes and error messages.
- All matching rules enabled → **On**; all disabled → **Off**; mixed states or
  configuration waiting to be applied → **Unknown**. No matches or failed
  communication → **Unavailable**. Attributes show the prefix, rule names, and
  enabled/total counts.

## How changes are made

The integration reads the current outbound configuration before each change,
matches the exact prefix, and submits each changed rule using the router's
`FIREWALL_modify` form. It preserves names and settings, verifies the saved rules
and order, calls the documented `POST /api/cmd.config.apply`, and confirms active
state before reporting success.

If the router already has pending edits, the integration asks you to apply or
discard them in Peplink first. Apply Changes is global to the router, so avoid
editing its configuration concurrently with an HA toggle. Failed or unexpected
saves are not applied or automatically discarded.

The write adapter supports Any/TCP/UDP/ICMP/IP/DSCP protocols and ordinary
Any/IP/network/MAC/domain/group/client address selectors and basic port ranges.
It rejects unrecognized fields or unsupported advanced settings before writing;
this prevents silently changing settings the adapter cannot preserve. IC2-managed
rules are also rejected. The form interface is firmware-specific and was inspected
on router firmware **8.6.1 build 6437**.

## Verification

Backend tests use HA Core 2026.10.1 and the custom-component test harness, with a
simulated router. They cover setup/options/reauth, integration loading, HA switch
services, authentication renewal, preservation and Save/Apply failures.

Live IC2 access, prefix/state reads and an unchanged-value Save were verified on
firmware 8.6.1 build 6437. Readback settings and rule order were preserved. Even an
unchanged Save produced pending changes. Live Apply was not tested.

HA OS installation, rendered setup/options UI, direct-router access and an actual
live enable/disable/application cycle remain unverified.

Run the tests:

```sh
uv sync
uv run pytest -q
uv run ruff check custom_components tests scripts generate_ic2_token.py
```

Create the installation ZIP:

```sh
uv run python -m scripts.package
```

Read a group with the integration's client (no settings are changed):

```sh
uv run python -m scripts.inspect_router --tag '[HA-A7K2]'
```

For direct access, populate `ROUTER_CLIENT_ID`, `ROUTER_CLIENT_SECRET`, and the
local `ROUTER_URL`, then add `--mode direct`.

## Generate an IC2 access token

Requires Python 3 and no additional packages. Put your development credentials in
`.env` beside the script:

```dotenv
IC2_CLIENT_ID=your_client_id
IC2_CLIENT_SECRET=your_client_secret
ROUTER_URL=https://your-router-remote-web-admin-host.peplink.com
```

Generate a token:

```sh
python3 generate_ic2_token.py
```

The script prints only the access token to standard output. Errors go to standard
error and return a nonzero exit code. It does not save tokens. Environment
variables override `.env` values; `IC2_CLIENT` is also accepted as the client ID.

To see the full response, including `expires_in` and the refresh token:

```sh
python3 generate_ic2_token.py --json
```

To use another credentials file:

```sh
python3 generate_ic2_token.py --env-file /path/to/.env
```

## Try the router API

```sh
source .env
IC2_ACCESS_TOKEN="$(python3 generate_ic2_token.py)" && \
  curl -sS --get --data-urlencode "access_token=$IC2_ACCESS_TOKEN" \
  "${ROUTER_URL%/}/api/info.firmware"
```

