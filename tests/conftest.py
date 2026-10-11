"""A simulated router: no live firewall changes are made by the test suite."""

from copy import deepcopy

import pytest
from aiohttp import web

TAG = "[HA-A7K2]"


@pytest.fixture
def config():
    def rule(name, enabled):
        return {
            "name": name,
            "enable": enabled,
            "policy": "deny",
            "protocol": {"type": "any"},
            "source": {"type": "mac", "mac": "00:11:22:33:44:55"},
            "destination": {"type": "any"},
            "logging": False,
        }

    return {
        "outbound": {
            "rule": {
                "9": rule(TAG + " iPad Pro", True),
                "10": rule(TAG + " Tablet", False),
                "11": rule("Description contains " + TAG, True),
                "12": rule("[HA-A7K2X] Other", False),
                "order": [12, 9, 11, 10],
            },
            "policy": "allow",
        },
        "inbound": {"rule": {"13": rule(TAG + " Inbound", True), "order": [13]}, "policy": "deny"},
        "private": {"rule": {"order": []}, "policy": "allow"},
        "localTraffic": False,
        "ids": {"enable": False},
        "reference": {"client": {"order": []}},
    }


class Router:
    def __init__(self, config):
        self.config = deepcopy(config)
        self.pending = False
        self.grants = []
        self.requests = []
        self.saves = []
        self.applies = 0
        self.token = ""
        self.reject_once = False
        self.refresh_rejected = False
        self.tamper = False
        self.save_rejected = False
        self.apply_rejected = False

    async def handle(self, req):
        self.requests.append((req.method, req.path, dict(req.query)))
        if req.path == "/oauth":
            grant = dict(await req.post())
            self.grants.append(grant)
            if grant["grant_type"] == "refresh_token" and self.refresh_rejected:
                return web.json_response({"error": "invalid_grant"}, status=400)
            self.token = "ic2-token-" + str(len(self.grants))
            return web.json_response(
                {
                    "access_token": self.token,
                    "expires_in": 172800,
                    "refresh_token": "refresh",
                }
            )
        if req.path == "/api/auth.token.grant":
            self.grants.append(await req.json())
            self.token = "device-token-" + str(len(self.grants))
            return web.json_response(
                {
                    "stat": "ok",
                    "response": {
                        "accessToken": self.token,
                        "expiresIn": 172800,
                    },
                }
            )
        if self.token not in {req.query.get("access_token"), req.query.get("accessToken")}:
            return web.Response(status=401)
        if req.path == "/api/config.firewall":
            if self.reject_once:
                self.reject_once = False
                return web.Response(status=401)
            # Reference information may change independently of firewall configuration.
            self.config["reference"] = {"live_counter": len(self.requests)}
            return web.json_response({"stat": "ok", "response": self.config})
        if req.path == "/cgi-bin/MANGA/chkactivate.cgi":
            return web.Response(
                text=(
                    "<response><activate><status>Activated</status>"
                    f"<modified>{int(self.pending)}</modified></activate></response>"
                ),
                content_type="application/xml",
            )
        if req.path == "/cgi-bin/MANGA/admin.cgi":
            form = dict(await req.post())
            self.saves.append(form)
            if self.save_rejected:
                return web.Response(text="<response><status>0</status></response>")
            assert form["section"] == "FIREWALL_modify" and form["direction"] == "o"
            assert "new_order" not in form
            rule = self.config["outbound"]["rule"][form["ruleid"]]
            assert form["rulename"] == rule["name"]
            assert form["srcmac"] == rule["source"]["mac"]
            assert form["policy"] == "drop"
            rule["enable"] = form.get("enable") == "yes"
            if self.tamper:
                rule["source"]["mac"] = "AA:AA:AA:AA:AA:AA"
            self.pending = True
            return web.Response(
                text="<response><status>1</status><errorMessage>Success</errorMessage></response>"
            )
        if req.path == "/api/cmd.config.apply":
            self.applies += 1
            if self.apply_rejected:
                return web.json_response({"stat": "fail"})
            self.pending = False
            return web.json_response({"stat": "ok"})
        return web.Response(status=404)


@pytest.fixture
async def router(config, socket_enabled):
    router = Router(config)
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", router.handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    router.url = f"http://127.0.0.1:{port}"
    try:
        yield router
    finally:
        await runner.cleanup()


@pytest.fixture(autouse=True)
def custom_integrations(enable_custom_integrations):
    yield
