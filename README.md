# sip-tester

SIP call replay tester that orchestrates SIP signaling and RTP playback from a PCAP capture.

## Example

```bash
sip-tester \
  --caller 1001 \
  --callee 1002 \
  --host pbx.example.com:5060 \
  --local-ip 192.168.1.10 \
  --pcap call.pcap \
  --ssrc-audio 0x11223344
```

## Orchestration flow

The app runs this sequence:

1. parse CLI
2. normalize URIs
3. resolve host
4. load PCAP
5. extract streams
6. build SDP
7. send INVITE
8. handle provisional responses (100/180/183)
9. if 183 has SDP, start early media RTP replay
10. receive 200 OK
11. send ACK
12. apply final media destination from 200 OK SDP
13. continue RTP replay (without restart) with final destination
14. handle INFO
15. send BYE
16. exit

## Early media support (183 Session Progress)

`sip-tester` supports SIP early media and provisional response handling:

- `100 Trying` and `180 Ringing` are logged and ignored.
- `183 Session Progress` without SDP is logged and ignored.
- `183` with SDP is parsed as an early media answer; RTP replay may start before call establishment.
- Multiple `183` responses with SDP update the active media destination without restarting replay.
- `200 OK` SDP applies final media destination; replay continues without schedule reset.
- If no early SDP is received, replay starts after `ACK`.
- `Require: 100rel` on provisional responses is rejected with `100rel/PRACK not supported`.


## SIP authentication

`sip-tester` supports optional SIP Digest authentication for the initial outbound `INVITE`.

- Provide both `--username` and `--password` to enable authentication.
- The client sends the initial `INVITE` without auth.
- If the server challenges with `401 WWW-Authenticate` or `407 Proxy-Authenticate` using Digest, `sip-tester` retries the `INVITE` with `Authorization` or `Proxy-Authorization`.
- If credentials are not provided and the server requires auth, `sip-tester` exits with a clear error.

Current MVP limitations:

- MD5 only (`algorithm=MD5` or omitted algorithm)
- `qop=auth` is supported
- `qop=auth-int` is not supported
- no repeated auth retry loops (single authenticated retry only)

### Example with authentication

```bash
sip-tester \
  --caller 1001 \
  --callee 1002 \
  --host pbx.example.com:5060 \
  --local-ip 192.168.1.10 \
  --pcap call.pcap \
  --ssrc-audio 0x11223344 \
  --username 1001 \
  --password secret
```

## Proxy-routed SIP dialog support

`sip-tester` supports dialog routing through common SIP proxy deployments (for example Kamailio/OpenSIPS-style Record-Route usage).

Dialog behavior implemented by the client:

- Initial `INVITE` includes generated `Via`, `Call-ID`, local `From` tag, `To` without tag, and `CSeq: 1 INVITE`.
- On `200 OK` to `INVITE`, the client stores:
  - remote target from `Contact` (used as Request-URI for in-dialog requests),
  - remote tag from `To`,
  - route set from `Record-Route` (UAC dialog order),
  - dialog identifiers (`Call-ID`, local tag, remote tag) and local CSeq progression.
- `ACK` for `2xx` and `BYE` are sent using dialog state:
  - Request-URI = remote target (`Contact` from `200 OK`),
  - `Route` header(s) derived from stored route set when present,
  - same dialog identifiers and correct CSeq handling.
- Incoming in-dialog `INFO` is matched by `Call-ID` and tags, then replied with `200 OK`.


## PCAP decoding

PCAP parsing uses the real [`github.com/google/gopacket`](https://github.com/google/gopacket) library and offline reader (`pcap.OpenOffline`).

- Decode starts from the capture link type reported by `handle.LinkType()` (not hardcoded Ethernet).
- RTP extraction uses decoded transport layers (`packet.TransportLayer()`) and reads RTP from UDP payload only.
- In `--debug` mode, packet decoding diagnostics include link type, layer stack, decode errors, and network/transport layer presence.

