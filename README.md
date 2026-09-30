# Kanki Tunnel

Kanki Tunnel is a tunnel panel for connecting an Iran server to a server abroad. It has a neon black-and-yellow interface in Persian and English.

> **Tunnel engine:** Based on BackPack by Amin Mohammadi (AminMGMT)
> https://github.com/AminMGMT/BackPack

Kanki is only the panel and installer. The tunnels themselves run on the official BackPack engine. The installer downloads it from BackPack's own releases and checks its checksum before installing.

## Install

Run this on **both** servers (Iran and abroad) as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kankiturk8770/kanki-tunnel/main/install.sh)
```

If the repo is **private**:

```bash
export GH_TOKEN=ghp_your_token
bash <(curl -fsSL -H "Authorization: Bearer $GH_TOKEN" https://raw.githubusercontent.com/kankiturk8770/kanki-tunnel/main/install.sh)
```

At the end, the installer prints the panel address and password. The password is shown **only once**.

## How to create a tunnel

1. Open the panel **on the Iran server**. Go to **Reverse tunnel** or **Direct tunnel**, fill in the form and press Create.
2. Copy the `kanki://` link it gives you.
3. Open the panel **on the abroad server**, go to **Join with link**, paste the link and press Connect.

| Tunnel | When to use it |
|---|---|
| Reverse + TCP Stealth | The common case: V2Ray and other panels, with anti-filtering |
| Reverse + UDP KCP FEC | Gaming, WireGuard, OpenVPN (UDP must be open) |
| Direct + TCP Stealth | When the Iran server blocks inbound connections |
| Direct + UDP FEC | Gaming when the Iran server blocks inbound connections (full IP tunnel) |

## The `kanki` command (terminal)

```
kanki              menu
kanki info         panel address and tunnel status
kanki password     change the panel password
kanki ssl DOMAIN   real SSL certificate (Let's Encrypt)
kanki update       update Kanki
kanki uninstall    remove it
```

## Offline install of the engine (if GitHub is blocked on the Iran server)

On a machine that can reach GitHub, download these two files from
https://github.com/AminMGMT/BackPack/releases/latest:

- `backpack_linux_amd64.tar.gz`
- `SHA256SUMS`

Copy both into `/root` on the server and run the installer again.
