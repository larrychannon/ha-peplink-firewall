# Peplink Router Firewall Toggle

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=larrychannon&repository=ha-peplink-firewall&category=integration)

Control your Peplink router’s **outbound firewall rules** with switches in Home
Assistant. Connect directly to your router or through InControl 2.

One switch can control one rule or a group of rules. Rules keep their order and
settings; the switch changes whether they are enabled.

## Install

Requires **Home Assistant 2026.10 or later** and **HACS**.

1. Click the **Open HACS Repository** button above and choose your Home Assistant instance.
2. Download **Peplink Router Firewall Toggle** in HACS.
3. Restart Home Assistant.

If the button does not open the repository, go to **HACS → ⋮ → Custom repositories**,
add `https://github.com/larrychannon/ha-peplink-firewall`, choose **Integration**,
and download it from HACS.

## Connect your router

1. Go to **Settings → Devices & services → Add integration**.
2. Search for **Peplink Router Firewall Toggle**.
3. Choose your connection method and enter its router URL, client ID and client secret:

   | Connection | Router URL | Credentials |
   | --- | --- | --- |
   | Direct router API | Your router’s local address, such as `https://192.168.50.1` | API client ID and secret created on the router |
   | InControl 2 | Your router’s Remote Web Admin address from InControl 2 | InControl 2 client ID and secret |

   The client must have permission to read and change router settings. Enter only
   the base router address, without a page path or extra URL parameters.
4. Give your first switch a name, such as **Block tablets**.
5. Copy the **Rule prefix** shown during setup.

Enter your credentials in this setup form. The integration handles sign-in and
renewal automatically.

## Choose which rules the switch controls

In your Peplink router’s web admin, put the switch’s prefix at the beginning of
one or more **Outbound Firewall Rule** names. For example, if HA generated
`[HA-A7K2]`:

```text
[HA-A7K2] Tablet
[HA-A7K2] Guest laptop
```

Save and apply those rule-name changes on the router. Keep any description after
the prefix; it does not affect matching. Use the same prefix for every rule you
want that switch to control. You can also enter an existing prefix during setup.

Add the switch to your HA dashboard or use it in automations.

**On enables the rules; Off disables them.** For a deny rule, On blocks the
matching traffic. For an allow rule, On enables that rule’s permission.

| Switch state | Meaning |
| --- | --- |
| On | All matching rules are enabled. |
| Off | All matching rules are disabled. |
| Unknown | The matching rules have different states, or router changes are waiting to be applied. |
| Unavailable | No matching rules were found, or HA cannot reach the router. |

## Manage your switches

Open the integration’s **Options** to add or remove switches or change how often
HA checks the router (every 30 seconds by default). Use **Reconfigure** to update
the connection or credentials. Removing a switch leaves its router rules as they are.

## Before toggling

Apply or discard any pending changes in the router’s web admin first. An HA toggle
saves and applies its changes, so avoid editing router settings at the same time.

Only outbound rules are supported. Rules managed by InControl 2 and rules with
unsupported advanced settings cannot be toggled by this integration.

**Compatibility:** router access has been checked on Peplink firmware 8.6.1.
Live switching and other firmware versions still need verification.
