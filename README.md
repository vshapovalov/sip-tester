# sip-tester

SIP call replay tester that orchestrates SIP signaling and RTP playback from a PCAP capture.

Supports two modes:
- `outbound` (default): initiates a call as UAC.
- `inbound`: registers, answers one inbound INVITE as UAS, replays RTP, sends BYE, exits.

## Example

```bash
sip-tester \
  --mode outbound \
  --caller 1001 \
  --callee 1002 \
  --host pbx.example.com:5060 \
  --local-ip 192.168.1.10 \
  --pcap call.pcap \
  --ssrc-audio 0x11223344
```

## Orchestration flow

### Outbound mode (`--mode=outbound`, default)

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

### Inbound mode (`--mode=inbound`)

1. parse CLI
2. normalize URIs (`--caller` is local identity/AoR)
3. resolve host
4. load PCAP
5. extract streams and build replay schedule
6. bind RTP sockets
7. build local SDP from actual bound RTP ports
8. send REGISTER
9. wait one incoming INVITE on the same SIP socket
10. send `180 Ringing`
11. wait 3 seconds
12. send `200 OK` with SDP
13. wait matching ACK
14. apply media destination from inbound INVITE SDP
15. start RTP replay
16. respond `200 OK` to in-dialog INFO while replay runs
17. send BYE after replay and wait `200 OK`
18. exit

## Mode-specific CLI semantics

- `--mode` allowed values: `outbound|inbound` (default: `outbound`).
- In `outbound` mode, `--callee` is required.
- In `inbound` mode, `--callee` is optional (not required).
- In `inbound` mode, `--caller` is treated as local AoR for REGISTER and dialog identity.

## RTP local sockets and SDP media ports

After local IP/family selection, `sip-tester` allocates and binds two RTP UDP sockets on that exact local IP:

- one socket for audio RTP,
- one socket for video RTP.

Port behavior:

- both ports are allocated from `10000-20000`,
- ports are bound before SDP offer generation,
- SDP `m=audio` and `m=video` advertise those exact bound ports,
- the same bound sockets are used for actual RTP sending (audio on audio socket, video on video socket),
- sockets stay open for the full call lifetime and are closed on shutdown/error.

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

`sip-tester` supports optional SIP Digest authentication for outbound `INVITE` and inbound-mode `REGISTER`.

- Provide both `--username` and `--password` to enable authentication.
- The client sends the initial request without auth.
- If the server challenges with `401 WWW-Authenticate` or `407 Proxy-Authenticate` using Digest, `sip-tester` retries the request with `Authorization` or `Proxy-Authorization`.
- If credentials are not provided and the server requires auth, `sip-tester` exits with a clear error.

Current MVP limitations:

- MD5 only (`algorithm=MD5` or omitted algorithm)
- `qop=auth` is supported
- `qop=auth-int` is not supported
- no repeated auth retry loops (single authenticated retry only per request)

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

PCAP parsing uses an internal, self-contained PCAP/PCAPNG reader (`internal/pcapio`) to keep builds deterministic and offline-friendly.

- Decode starts from the capture link type in the packet metadata (`pcap` global link type or `pcapng` interface link type), not hardcoded Ethernet.
- RTP extraction uses lightweight decoded packet metadata (`DecodedPacket`) and reads RTP from UDP payload only.
- In `--debug` mode, packet decoding diagnostics include timestamp, link type, decode errors, IP/protocol/ports, and payload length.
