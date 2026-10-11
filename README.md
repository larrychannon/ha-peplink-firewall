# Peplink Home Assistant development

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
