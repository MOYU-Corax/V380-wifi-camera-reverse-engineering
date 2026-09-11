# V380 Wi-Fi camera — reverse engineering

Stream a **V380 / "macrovideo"** Wi-Fi camera on your LAN **without the vendor app** —
full protocol documentation and a zero-dependency Node client that serves MJPEG over HTTP.

No cloud account. No app. No phone. The camera runs a plain TCP server; once you speak its
protocol you just read frames off a socket.

- 📖 **[PROTOCOL.md](PROTOCOL.md)** — the protocol documented byte-by-byte: discovery,
  AES login, media-key derivation, frame framing and decryption.
- 🎥 **[`v380-mjpeg.js`](v380-mjpeg.js)** — working client, **zero dependencies**, ~350 lines.
- 🧪 Sibling project: **[CY365-wifi-camera-reverse-engineering](https://github.com/26medias/CY365-wifi-camera-reverse-engineering)**
  — same goal, a far nastier encrypted-P2P camera.

---

## Does my camera match?

| | |
|---|---|
| **App** | "V380" / "V380 Pro" |
| **Reference unit** | model `AC54`, EXIF manufacturer `JLDV`, `deviceVersion 31` |
| **Bought from** | [this AliExpress listing](https://www.aliexpress.com/item/1005009307282734.html) |
| **Open port** | **TCP 8800** ← the giveaway |
| **Video out** | MJPEG 640×480 (other units in the family emit H.264/H.265) |
| **Family marker** | the login key string `macrovideo+*#!^@` inside the app |

If `nmap -p 8800 <camera-ip>` is open, you're almost certainly in the right place.

---

## Quick start

```bash
git clone https://github.com/26medias/V380-wifi-camera-reverse-engineering
cd V380-wifi-camera-reverse-engineering

cp config.example.sh config.sh   # then edit: device id, password, (optional) MAC
./run-v380.sh
```

Then open **<http://localhost:8090/>**.

| endpoint | what you get |
|---|---|
| `/` | live view page |
| `/stream` | `multipart/x-mixed-replace` MJPEG — works in VLC, browsers, Home Assistant |
| `/snapshot` | latest single JPEG |

Or drive the client directly:

```bash
node v380-mjpeg.js --id 12345678 --password 'yourpass' --mac aa:bb:cc:dd:ee:ff --http 8090
```

Requires **Node 18+** and nothing else. (`nmap` is used only as a rare fallback when
re-finding the camera by MAC.)

---

## ⚠ The gotcha that blocks every other tool

**The username is the device ID, not `admin`.**

Every existing V380 tool defaults to `admin`, which this firmware rejects with result code
`1011 (invalid username)`. The username that works is the camera's **device id as a decimal
string** — the same number printed on the device.

The login result codes are a gift when debugging, because they tell you *which half* of the
credential is wrong:

| code | meaning |
|------|---------|
| `1001` | OK |
| `1011` | invalid **username** |
| `1012` | invalid **password** |
| `1018` | invalid device id |

---

## How it works (30-second version)

```
UDP broadcast "NVDEVSEARCH^100" -> :10008        # find camera + device id
TCP :8800  cmd 1167 (auth)   -> 1168 + authTicket
TCP :8800  cmd 301  (stream login, carries the ticket) -> 401 + width/height
TCP :8800  cmd 303  (start)
           -> 0x7F-framed fragments -> reassemble -> AES-decrypt -> JPEG
```

Media is **partially** AES-128-ECB encrypted: 64 bytes of every 80-byte window, keyed by
`u32le(authTicket) ++ 0x618123462c14795c ++ 0x82800df0`.

Full details, byte tables and result codes: **[PROTOCOL.md](PROTOCOL.md)**.

---

## Features

- **Auto-detects the camera's IP** — native discovery, then by MAC address; re-resolved on
  every reconnect, so DHCP lease changes don't break it.
- **Self-healing** — the camera can go silent on a still-open socket; a watchdog reconnects
  after 8 s of no frames.
- **Zero dependencies** — Node stdlib only.

### Known behaviours

- **Single session.** The camera serves one client. If you open the phone app, this client
  goes dark until you close it (and then recovers on its own).
- **Silent stalls.** Handled by the watchdog — see above.
- **Not all units are MJPEG.** If a decrypted payload doesn't start `FF D8`, you have an
  H.264/H.265 unit — pipe the elementary stream to ffmpeg instead of carving JPEGs.

---

## Security notes

This is worth stating plainly, because it's the real finding:

- The password is **obfuscated, not encrypted**. It's AES-ECB'd with a random key `rk`…
  which is transmitted **in the same packet**, under a constant key (`macrovideo+*#!^@`)
  compiled into every copy of the app. Anyone who captures one login recovers the password.
- The media key is 12 bytes of **hard-coded constant** plus a 4-byte ticket the camera
  hands you in plaintext. There is no key exchange and no secret.
- Treat V380 credentials as public on any network you don't control, and keep these cameras
  off your main VLAN.

**Do not commit your own credentials.** `config.sh` is gitignored for this reason. On this
camera family the device id *is* the username, so a device-id + password pair is a complete
credential — don't paste them into issues.

---

## Repo contents

| file | what |
|---|---|
| `PROTOCOL.md` | the full reverse-engineered protocol spec |
| `v380-mjpeg.js` | the client (zero dependencies) |
| `run-v380.sh` | launcher; reads `config.sh` |
| `config.example.sh` | template — copy to `config.sh` |

---

## Prior art

- [`PyanSofyan/V380Decoder`](https://github.com/PyanSofyan/V380Decoder) — C#/.NET. The best
  existing reference; correct protocol, but defaults the username to `admin` (see above).
- [`prsyahmi/v380`](https://github.com/prsyahmi/v380) — C. Implements the **pre-encryption**
  protocol; fails on `deviceVersion 31` firmware with `-11 / unknown 0x9c`.

This repo adds: the device-id-as-username finding, a dependency-free client with IP
auto-detection and stall recovery, and a protocol document written to be implementable
from scratch.

---

## Legal

Research on **hardware I own, on my own network**, for interoperability — getting a local
video stream out of a camera without routing it through a vendor cloud. Point it only at
cameras you own. No vendor firmware is copied, modified or redistributed here.

## License

MIT — see [LICENSE](LICENSE).
