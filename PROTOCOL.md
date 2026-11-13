# V380 camera protocol (reverse-engineered)

How to pull the live video stream off a **V380 / "macrovideo"** Wi‑Fi camera without the
vendor app, over the LAN, with no cloud involvement.

- **Reference unit:** model `AC54` (EXIF manufacturer `JLDV`), `deviceVersion = 31`,
  640×480. Sold under many brand names; the family is identified by the app "V380 Pro"
  and the login key string `macrovideo+*#!^@`.
- **Working client:** [`v380-mjpeg.js`](v380-mjpeg.js) (Node, no dependencies) — launcher
  [`run-v380.sh`](run-v380.sh).
- **Difficulty:** easy. The camera runs a plain **TCP server on port 8800**. No cloud, no
  P2P, no NAT traversal. Contrast with [CY365](https://github.com/26medias/CY365-wifi-camera-reverse-engineering), which is a nightmare.

---

## 0. TL;DR

```
UDP  broadcast "NVDEVSEARCH^100" -> :10008        # find camera + device id
TCP  :8800  cmd 1167  (auth)      -> 1168 + authTicket
TCP  :8800  cmd 301   (stream login, carries authTicket) -> 401 + w/h
TCP  :8800  cmd 303   (start)
     then read 0x7F-framed fragments, reassemble, AES-decrypt -> JPEG
```
**The single biggest gotcha: the username is the DEVICE ID, not `admin`.**

---

## 1. Byte order and connection model

- **All integers are little-endian.** (Unlike the CS2/PPPP family, which is big-endian.)
- The client opens **two separate TCP connections** to `:8800`:
  1. **Auth connection** — send `1167`, read `1168`, grab the ticket, **close it**.
  2. **Stream connection** — send `301` (with the ticket), then `303`, then read media.
- The camera is effectively **single-session**: it will serve the phone app *or* your
  client, not both. If the app connects, your stream dies (see §8).

---

## 2. Discovery (optional)

Bind a UDP socket to port **10009**, enable broadcast, and send the ASCII string
`NVDEVSEARCH^100` to **255.255.255.255:10008**. Cameras reply with a `^`-delimited record:

```
NVDEVRESULT^200^aa:bb:cc:dd:ee:ff^192.168.1.50^255.255.255.0^192.168.1.1^5040^5050^5051^8800^7050^5040^12345678^0^1
             |  |                 |             |             |                        |    |
           code MAC               IP            netmask       gateway            (ports…)  device id
```
Fields: `[2]`=MAC, `[3]`=IP, `[4]`=netmask, `[5]`=gateway, `[9]`=media port (8800),
`[12]`=**device id** (the number printed on the camera; also your username).

> **Caveat:** on the reference unit this discovery is *unreliable* — it often does not
> answer at all, especially while a session is active. `v380-mjpeg.js` therefore falls
> back to finding the camera by **MAC address** in the host ARP table (`ip neigh`, with an
> `nmap -sn` sweep to populate it). The MAC is hardware-stable, so this survives DHCP
> lease changes, which is what you actually want for a long-running client.

---

## 3. Authentication — command 1167

Open TCP to `<ip>:8800` and send a **520-byte** buffer:

| offset | size | value |
|--------|------|-------|
| 0  | u32 | `1167` (command) |
| 4  | u32 | `120` (LAN) — `1022` for the cloud/relay variant |
| 8  | u8  | `31` (protocol version) |
| 9  | u32 | `1` |
| 13 | u32 | **device id** |
| 49 | 32B | **username**, ASCII, NUL-padded |
| 81 | 64B | **encrypted password** (see §3.1) |

Remaining bytes are zero.

### 3.1 Password obfuscation (`GeneratePassword`)

```
sk  = "macrovideo+*#!^@"            # fixed 16-byte ASCII key, same on every camera
rk  = 16 random ASCII alphanumerics # per-login random key
pad = 48 bytes: password in ASCII, zero-padded

pad = AES-128-ECB-Encrypt(sk, pad)  # 3 blocks, NO padding
pad = AES-128-ECB-Encrypt(rk, pad)  # encrypted again with the random key

wire = rk (16 bytes)  ||  pad (48 bytes)      # 64 bytes total
```

> **Security note for the reader:** `rk` is sent **in the clear** in the same packet, and
> `sk` is a constant compiled into every app. So this is obfuscation, not encryption —
> anyone who captures one login can recover the plaintext password by decrypting with
> `rk` and then with `sk`. Treat V380 passwords as public on any network you don't trust.

### 3.2 Response — command 1168

Read at least 60 bytes:

| offset | size | meaning |
|--------|------|---------|
| 0  | u32 | `1168` |
| 4  | u32 | **result** |
| 12 | u8  | `deviceVersion` (31 on the reference unit) |
| 13 | u32 | **authTicket** — needed for §4 and the media key |
| 17 | u32 | sessionId |

Result codes:

| code | meaning |
|------|---------|
| `1001` | **OK** |
| `1011` | invalid username |
| `1012` | invalid password |
| `1018` | invalid device id |

> ### ⚠ The username gotcha
> Every existing tool defaults the username to `admin`. On this unit `admin` returns
> **1011 (invalid username)**. The username that works is the **device id as a decimal
> string** (e.g. `"12345678"`). If you get 1011, sweep candidates — the distinction
> between 1011 and 1012 tells you which half of the credential is wrong, which makes
> this trivially diagnosable.

Close the auth connection once you have the ticket.

---

## 4. Stream login — command 301

Open a **new** TCP connection to `:8800` and send **256 bytes**:

| offset | size | value |
|--------|------|-------|
| 0  | u32 | `301` |
| 4  | u32 | device id |
| 8  | u32 | `0` |
| 12 | u16 | `20` (communication version) |
| 14 | u32 | **authTicket** from §3.2 |
| 22 | u32 | `4097` = audio on (`4096` = off) |
| 26 | u32 | quality: `0` = SD, `1` = HD |

### Response — command 401 (read ≥26 bytes)

| offset | size | meaning |
|--------|------|---------|
| 0  | u32 | `401` |
| 4  | i32 | result — **`-11` / `-12` = failure** |
| 8  | u16 | `communicationVersion` (20) |
| 10 | u32 | frame width |
| 14 | u32 | frame height |
| 18 | u32 | maxPackSize |

Then **start the stream** by sending another 256-byte buffer on the *same* connection:

| offset | size | value |
|--------|------|-------|
| 0 | u32 | `303` |
| 4 | u16 | `0x3001` |

Media begins flowing on this connection immediately.

---

## 5. Media key derivation

Only when `deviceVersion > 30` (i.e. the encrypted-media firmware):

```
key[0..3]   = u32le(authTicket)
key[4..11]  = u64le(0x618123462c14795c)
key[12..15] = u32le(0x82800df0)
```

Example: ticket `64370` → `72FB0000 5C79142C 46238161 F00D8082`.

> Note that **12 of the 16 key bytes are a hard-coded constant** and the other 4 are a
> ticket the camera just told you in plaintext. There is no key exchange and no secret.

---

## 6. Media framing

The stream is a sequence of **fragments**, each with a 12-byte header:

| offset | size | meaning |
|--------|------|---------|
| 0 | u8  | **`0x7F` magic** — resync on this |
| 1 | u8  | **type** (see table) |
| 3 | u16 | `totalFragments` for this frame |
| 5 | u16 | `fragmentIndex` (0-based) |
| 7 | u16 | `payloadLen` |

followed by `payloadLen` bytes. Bytes 2 and 9–11 are unused.

**Fragment types**

| type | meaning |
|------|---------|
| `0x00` | video, I-frame |
| `0x01` | video, P-frame |
| `0x28` / `0x29` | video, alternate encoding (firmware v32+) |
| `0x09` | video — **what the reference unit sends (MJPEG)** |
| `0x1A` | audio (G.711) |
| `0x16` | audio/telemetry — observed on a `deviceVersion=3` unit: fixed 272-byte payloads, not decoded |
| `0x5B` | control / ignore |

### Reassembly

Concatenate the payloads of `fragmentIndex` `0 … totalFragments-1`. The assembled buffer
starts with a **16-byte inner frame header**:

| offset | size | meaning |
|--------|------|---------|
| 0 | u32 | frameId |
| 4 | u16 | frameType |
| 6 | u16 | frameRate |
| 8 | u64 | timestamp |

Everything after byte 16 is the media payload.

---

## 7. Media decryption

For `deviceVersion > 30`, the payload is **partially** AES-128-ECB encrypted with the
media key from §5:

```
for (off = 0; off + 64 <= len; off += 80)
    decrypt 64 bytes (4 AES blocks) in place at off
    # the following 16 bytes are left as-is
```

So each 80-byte window is 64 bytes ciphertext + 16 bytes plaintext, and any tail shorter
than 80 bytes is plaintext. Audio (`0x1A`) is simpler: straight AES-ECB over
`floor(len/16)*16` bytes.

> `communicationVersion == 21` uses a different scheme (decrypt the first 2048 bytes, or
> the whole 16-byte-aligned buffer). Present in the reference implementations, untested
> here.

**Result:** on this unit the decrypted payload is a complete **JPEG** (`FF D8 … FF D9`),
i.e. the camera streams **MJPEG**, not H.264 — despite the app shipping an H.264 decoder.
Other cameras in the family emit H.264/H.265 on types `0x00/0x01`. Sniff the first bytes
of a decrypted payload to find out which you have.

> **Second unit observed** (`deviceVersion=3`, 1280×720): plaintext (no media key, as
> expected for `deviceVersion ≤ 30`) **H.264 Annex B** on types `0x00/0x01` at ~9 fps.
> I-frames are self-contained (`SPS + PPS + IDR`), so a client can join mid-stream and
> starts decoding at the next I-frame (~1 s). `--quality 0` switches it to 640×480 but
> *not* to MJPEG — the codec is fixed per unit, only the resolution changes.

Serving it is then trivial: emit each JPEG as `multipart/x-mixed-replace` and any browser
or VLC will play it.

---

## 8. Operational gotchas

- **Single session.** The camera streams to one client. Open the phone app and your
  client goes dark; close the app and it comes back.
- **Silent stalls.** The camera can stop sending while the TCP socket stays `ESTABLISHED`
  — no FIN, no error. A naive client hangs forever. Use a **watchdog**: if no frame
  arrives for ~8 s, destroy the socket and reconnect. `v380-mjpeg.js` does this.
- **DHCP churn.** Re-resolve the camera's IP on *every* reconnect (see §2), don't cache it
  at startup.
- **Non-JPEG payloads.** If the decrypted payload doesn't start `FF D8`, you have an
  H.264/H.265 unit — pipe the elementary stream to ffmpeg instead of carving JPEGs.

---

## 9. Why the existing tools fail

| tool | outcome on this unit |
|------|----------------------|
| [`prsyahmi/v380`](https://github.com/prsyahmi/v380) (C) | Speaks the **pre-encryption** protocol. Login is rejected with `Login response: unsupported -11` and `Unknown 0x9c command`; zero bytes of video. It has no concept of the 1167/AES login or the media key. |
| [`PyanSofyan/V380Decoder`](https://github.com/PyanSofyan/V380Decoder) (C#/.NET) | Correct protocol — this is the best reference — but it defaults `--username admin`, which returns **1011** here. Pass the device id as the username and it works. |
| SD-card `ceshi.ini` RTSP trick | Some firmware exposes native RTSP if you boot with a FAT32 card containing `[CONST_PARAM]\nrtsp = 1`, giving `rtsp://user:pass@ip:554/live/ch00_0`. Hit-and-miss by hardware batch; some units factory-reset instead. Worth 5 minutes before writing code. |

---

## 10. Reproducing this on a different unit

1. **Find it:** `NVDEVSEARCH` broadcast, or just match its MAC OUI in your ARP table.
   Port `8800` open ⇒ V380 family.
2. **Get the device id** from discovery or the sticker; it's both an identifier *and* the
   username.
3. **Try login** with the device id as username. The 1011/1012/1018 result codes tell you
   exactly what's wrong — this is the fastest oracle you have, use it.
4. **Check `deviceVersion`** in the 1168 reply. `> 30` ⇒ encrypted media, derive the key.
5. **Dump one decrypted payload to disk** and run `file` on it. That single step tells you
   MJPEG vs H.264 and saves you from guessing at the container.

The whole protocol is plaintext-framed and the "crypto" is a constant, so a Wireshark
capture plus the two reference implementations above is enough to bring up a new variant
in an afternoon.
