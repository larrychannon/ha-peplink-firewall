# Peplink Outbound Firewall for Home Assistant

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=larrychannon&repository=ha-peplink-firewall&category=integration)

A custom integration for Home Assistant 2026.10. Each switch enables or disables
existing **Outbound Firewall Rules** whose names start with its prefix, for example:

```text
[HA-A7K2] iPad Pro
[HA-A7K2] Another device
```

The description after the prefix is ignored for matching. HA does not create,
rename, delete, or reorder router rules. **On means the rules are enabled**: for a
Deny rule, On means its traffic is blocked. Inbound, internal, and local-service
rules are outside the integration's scope.

## Install on HA OS

### HACS

This is a **custom integration**, installed through HACS rather than the HA OS
add-on store. HACS must already be installed in your Home Assistant instance.

1. Click the **Open HACS Repository** button above and choose your HA instance.
2. Add/download **Peplink Outbound Firewall** when prompted, then restart HA.
3. Follow the setup instructions below, starting at step 3.

If the button cannot find the repository, open **HACS → ⋮ → Custom repositories**,
add `https://github.com/larrychannon/ha-peplink-firewall` with type **Integration**,
then find and download it in HACS. This repository is not in the default HACS
catalogue. Without a published release, HACS installs its default branch.

### Manual installation and setup

1. Copy `custom_components/peplink_firewall` into your HA configuration directory,
   resulting in `/config/custom_components/peplink_firewall/manifest.json`. The
   release ZIP has the same folder structure and can be extracted into `/config`.
2. Restart **Home Assistant**.
3. Open **Settings → Devices & services → Add integration → Peplink Outbound Firewall**.
4. Choose **Direct router API** or **InControl 2 Remote Web Admin** and enter the
   base router URL and the client ID/secret for that connection method. Use a
   client with permission to read and modify router configuration.
5. Name your first switch. The integration generates a prefix; copy it into the
   start of the router rule names. To reuse the development rule, enter
   **`[HA-A7K2]`** instead of the generated prefix.
6. Add the switch to a dashboard or use it in automations.

The router's options UI lets you add/remove tagged switches and set the polling
interval (default 30 seconds). Removing a switch leaves router rules unchanged.
Use the integration's **Reconfigure** action to change connection settings or
credentials. On reconfiguration, an omitted/blank secret keeps the stored secret.

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

Local tests use **HA Core 2026.10.1** with the HA custom-component test harness.
They exercise HA config/options/reauth flows, switch states, and HTTP calls to a
simulated router, including token renewal, preservation, pending edits, and Save/
Apply failures. These are backend tests, not a deployment on the user's HA OS VM
or a rendered HA frontend test.

Live IC2 access, prefix/state reads, and a token-based Save with unchanged values
have been verified against the development router. All readback settings and rule
order were preserved. Peplink marked that Save as pending even though its values
were unchanged; the user must apply/discard those pending edits before toggling
through the integration. Apply was not called on the live router, at the user's request. Direct
router access and actual enable/disable/application on the HA OS VM remain to be
verified after installation.

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

Verified against the development router: an IC2 token in the `access_token` URL
parameter returns firmware information, with active firmware `8.6.1 build 6437`.
Python's default urllib User-Agent received HTTP 403 with `error code: 1010`;
curl and urllib using curl's User-Agent returned HTTP 200 with the same token.
Firewall rule control has not yet been verified.
