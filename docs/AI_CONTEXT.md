# sip-tester AI Context and Design Document

This document is the canonical engineering context for AI-assisted development of `sip-tester`.
It is designed so an AI agent can understand architecture, behavior, boundaries, and intent without reading the entire source tree.

---

## 1. Project Overview

### What `sip-tester` is

`sip-tester` is a **deterministic outbound SIP call replay tool**. It is a CLI application that:

- initiates one outbound SIP call (UAC behavior),
- extracts SIP/SDP and RTP metadata from a PCAP capture,
- negotiates media using a regenerated SDP offer,
- replays captured RTP payload as outbound UDP RTP traffic.

At a high level, it behaves like a focused “call replayer” for test environments rather than a generic softphone or SBC.

### Why it exists

The project exists to provide a practical, scriptable way to recreate real call behavior from production-like captures for validation and troubleshooting of SIP+RTP infrastructure.

Primary motivation:

- Existing testing tools (especially SIPp-based flows) are strong for signaling scripting,
- but weaker for **realistic RTP replay** (especially mixed media streams and IPv6 scenarios),
- and often require approximating media rather than reproducing captured behavior.

### Problems it solves

`sip-tester` solves these specific testing gaps:

- **Outbound SIP call generation with real media replay** from PCAP.
- **Deterministic RTP packet emission** based on capture timing.
- **IPv4 + IPv6 operation** controlled by explicit local bind IP.
- **Media fidelity** by preserving packet-level RTP fields (sequence, timestamp, marker, payload type, SSRC, payload bytes).
- **Infrastructure validation** for SBCs, proxies, media relays, recorders, and pipelines that depend on realistic media timing and packet ordering.

---

## 2. Core Use Case

### Main scenario

A user has a PCAP that includes:

- a SIP `INVITE` containing SDP,
- RTP streams (audio, video, or both),
- known SSRC values for the stream(s) to replay.

The user wants to:

- recreate the call from an endpoint under their control,
- negotiate media through SIP,
- send RTP packets with the same packet-level contents and relative timing as capture,
- validate behavior of downstream infrastructure (SBC/proxy/media pipeline/transcoder/analytics/recording).

### Why SIPp is often insufficient here

In this project’s problem framing, SIPp limitations are primarily about media realism and control:

- weak or awkward RTP replay fidelity for complex captures,
- practical difficulties with **IPv6-focused replay scenarios**,
- less precise control over concurrent audio/video packet ordering and pacing,
- inability to directly reuse captured packet fields end-to-end in a deterministic replay path.

`sip-tester` addresses this by treating PCAP as source-of-truth for RTP packet data and timing.

---

## 3. High-Level Architecture

`sip-tester` is organized as composable internal packages:

- `internal/cli`: CLI parsing, validation, URI normalization, SSRC parsing.
- `internal/config`: runtime configuration struct and required-flag checks.
- `internal/netutil`: host:port parsing utilities.
- `internal/pcapread`: PCAP load, INVITE/SDP extraction, RTP extraction/grouping.
- `internal/sdp`: SDP offer builder from extracted media metadata + current local IP.
- `internal/sipclient`: outbound SIP client and dialog primitives (INVITE/ACK/BYE/INFO response).
- `internal/replay`: RTP schedule creation and paced UDP sender.
- `internal/app`: orchestrator for end-to-end runtime flow.
- `cmd/sip-tester`: CLI entrypoint invoking app orchestration.

### Component responsibilities

1. **CLI / config**
   - Parse required flags.
   - Normalize caller/callee to SIP URIs.
   - Parse local IP and infer IP family.
   - Parse host/port and SSRC values.

2. **PCAP reader**
   - Decode all packets from PCAP.
   - Locate first SIP INVITE with SDP body.
   - Parse SDP media attributes (`m=`, `a=rtpmap`, `a=fmtp`).
   - Parse RTP packets from UDP and group by SSRC.

3. **SDP extractor / builder**
   - Reuse media metadata from captured SDP.
   - Generate fresh offer with runtime IP/ports.

4. **RTP stream extractor**
   - Select user-requested streams by SSRC.
   - Preserve packet-level RTP fields and payload.

5. **Replay scheduler**
   - Build replay offsets from packet capture timestamps.
   - Support merged timeline semantics (audio+video).

6. **SIP client**
   - Send INVITE and parse 200 response/SDP answer.
   - Send ACK.
   - Maintain simple dialog state for INFO/BYE.

7. **RTP sender**
   - Emit marshaled RTP over UDP according to schedule.

8. **Orchestrator**
   - Coordinates signaling lifecycle and media replay.
   - Handles incoming INFO with 200 OK.
   - Sends BYE at replay completion.

### Data flow summary

`CLI args -> Config -> Host resolution + PCAP load -> INVITE SDP + RTP extraction -> SDP offer build -> SIP INVITE/200/ACK -> SDP answer media targets -> RTP replay -> BYE -> exit`

---

## 4. Execution Flow (Step-by-step)

This is the exact runtime sequencing model used by the app orchestrator.

1. **Parse CLI**
   - `cli.ParseArgs` validates required flags and builds typed config.

2. **Normalize caller/callee**
   - bare user values become `sip:user@host` using CLI host.
   - existing `sip:` URIs are left unchanged.

3. **Resolve host using local-ip family intent**
   - Runtime resolves host via DNS.
   - Operational design intent: chosen target address should match the local bind IP family.
   - Current implementation resolves host and uses first returned IP.

4. **Read PCAP**
   - Entire file decoded into packet slice.

5. **Extract INVITE SDP**
   - First SIP INVITE with `Content-Type: application/sdp` body is selected.

6. **Extract media metadata**
   - Parse audio/video `m=` sections and codec attributes.

7. **Extract RTP streams by SSRC**
   - Parse UDP RTP packets.
   - Group by SSRC and sort each stream by capture time.
   - Select only user-requested audio/video SSRCs.

8. **Build global replay schedule (capture timestamp-based)**
   - Replay timing derives from capture timestamp deltas.
   - Scheduler can produce a single merged timeline preserving cross-stream ordering.

9. **Build SDP offer**
   - New SDP built with current local IP and fixed local media ports.
   - Payload metadata copied from captured SDP.

10. **Send SIP INVITE**
    - Offer SDP included.

11. **Receive 200 OK**
    - Parse SDP answer for remote connection IP and media ports.

12. **Parse SDP answer**
    - Extract answer-level `c=` IP and each media `m=` port/protocol/formats.

13. **Send ACK**
    - Finalize INVITE transaction/dialog establishment.

14. **Start RTP replay**
    - For negotiated media types present in answer and selected by SSRC.

15. **Respond 200 OK to INFO**
    - While replay is running, inbound INFO requests are accepted and answered `200 OK`.

16. **Finish replay**
    - Replay goroutines complete after last scheduled packet.

17. **Send BYE**
    - Terminate dialog cleanly.

18. **Exit**
    - Process returns success if all steps completed.

---

## 5. CLI Semantics

### Required flags

- `--caller`
  - Caller identity as SIP URI or bare user.
- `--callee`
  - Callee identity as SIP URI or bare user.
- `--host`
  - Remote SIP destination in `host:port` form.
  - Supports DNS names, IPv4, and bracketed IPv6 literal with port.
- `--local-ip`
  - **Literal local IP** to bind signaling/media sockets.
  - Determines IP family model (`ipv4` or `ipv6`).
- `--pcap`
  - Path to PCAP file to replay.
- `--ssrc-audio` and/or `--ssrc-video`
  - At least one must be provided.

### Optional flags

- `--debug`
  - Present in CLI schema; can be used for expanded diagnostics if wired into logging.

### Normalization rules

- If value starts with `sip:`, keep unchanged.
- Otherwise normalize to `sip:<raw>@<host-from---host>`.
- Host for normalization ignores port from `--host`.

Example:

- `--caller 1001 --host pbx.example.com:5060` -> `sip:1001@pbx.example.com`

### SSRC parsing

- Supports decimal (`287454020`) and hex (`0x11223344`).
- Parsed as unsigned 32-bit integer.
- Invalid / empty input raises CLI error.

### Host resolution rules

- `--host` is split into host and port.
- Host may be DNS name or IP literal.
- Runtime resolves to network address for SIP transport.
- Design expectation is family compatibility with `--local-ip`.

### IPv4/IPv6 detection from `--local-ip`

- `To4() != nil` => IPv4.
- Otherwise => IPv6.
- This family signal should drive:
  - socket bind behavior,
  - destination selection,
  - SDP `c=` address family and IP.

---

## 6. SIP Behavior

### Scope

- **Outbound-only UAC** behavior.
- No REGISTER.
- No inbound call establishment (not a UAS for INVITE).

### Dialog/signaling profile

- Send one initial INVITE with SDP offer.
- Wait for final non-1xx response (expects 200 OK).
- Parse answer SDP.
- Send ACK.
- Build and persist dialog routing state from `200 OK` to `INVITE`:
  - `Call-ID`,
  - local `From` tag,
  - remote `To` tag,
  - remote target from `Contact`,
  - route set from `Record-Route` (UAC route-set order),
  - local CSeq progression.
- During replay, listen for INFO and answer 200 OK.
- Send BYE at end and require 200 OK.

### INFO handling

- Incoming INFO is matched to the active dialog using `Call-ID` and tags.
- Response is always `200 OK` for parsed INFO requests.
- Useful for systems that send mid-call telemetry/control INFO.

### ACK and BYE

- ACK is sent after successful 200 INVITE response.
- ACK Request-URI targets remote target (`Contact` from 200 OK), and includes dialog `Route` header(s) when route set exists.
- BYE is sent as an in-dialog request with Request-URI set to remote target and route set applied via `Route` header(s).
- BYE increments CSeq and waits for 200 response.

### Request-URI vs From/To logic

- Request-URI for initial INVITE uses normalized `toURI` (callee URI).
- Request-URI for in-dialog ACK/BYE/INFO uses remote target from `Contact` in the `200 OK` to INVITE.
- `From` uses normalized caller URI plus generated local tag.
- `To` on initial INVITE uses callee URI; in-dialog requests reuse remote `To` header returned by 200 OK.
- When `Record-Route` is present in the 200 OK to INVITE, in-dialog requests include corresponding `Route` headers from stored route set.

---

## 7. SDP Handling

### Source of SDP metadata

- SDP is extracted from first INVITE-with-SDP found in PCAP.
- Parsed media metadata from capture is used to build a new offer.

### What is reused

Per media section (`audio` / `video`):

- payload types from `m=` list,
- `a=rtpmap` mappings,
- `a=fmtp` parameters.

### What is regenerated/overridden

- session-level and connection IP values (`o=` and `c=`) use runtime `--local-ip`.
- media ports are regenerated by tool defaults:
  - audio: 4000
  - video: 4002

### What is intentionally not copied

- ICE attributes,
- DTLS fingerprints,
- SRTP crypto lines,
- original captured media IP/ports,
- other endpoint-specific transport negotiation state.

This keeps negotiation simple and deterministic for plain RTP over UDP testing.

---

## 8. RTP Replay Design

> Critical behavior: RTP is **replayed**, not synthesized.

### Fidelity model

For each selected RTP packet, the sender preserves:

- RTP payload bytes,
- sequence number,
- RTP timestamp,
- marker bit,
- payload type,
- SSRC.

The sender rebuilds a standard RTP header and appends original payload bytes.

### Pacing source of truth

- Replay pacing is based on **packet capture timestamps** (`pcap capture time`), not RTP timestamp math.
- Relative inter-packet timing from capture is reproduced as wall-clock send delays.

Why this matters:

- RTP timestamps represent media clock units and vary by codec/sample rate.
- Capture deltas directly represent observed packet spacing through the original sender/network path.
- For infrastructure testing, capture-based pacing is typically the most faithful replay signal.

### Global replay schedule concept

- Scheduler logic supports merging audio and video packets into one timeline ordered by capture time.
- This preserves cross-stream interleaving and avoids race-induced reordering.

### Why not independent unsynchronized loops

If each stream is replayed in isolation without a shared timeline, relative ordering between audio and video can drift due to scheduler jitter and goroutine timing. A global schedule improves deterministic behavior and reproducibility.

### Deterministic replay value

Determinism is needed for:

- reproducible bug reports,
- regression tests against SBC/media pipeline changes,
- stable latency/jitter analysis across runs,
- consistent packet-count and ordering expectations.

### Current runtime note

- Core scheduler package supports merged scheduling.
- Orchestrator currently starts replay per negotiated media target; deterministic per-stream pacing is preserved, while cross-stream ordering depends on concurrent senders.

---

## 9. SSRC Selection

### Model

- User explicitly provides SSRC(s) via CLI.
- Tool extracts all RTP streams by SSRC from PCAP.
- Replay includes only selected SSRC stream(s).

### Why explicit SSRC is required

PCAPs frequently contain:

- multiple calls,
- retransmissions or parallel media,
- bidirectional legs,
- unrelated background RTP.

Explicit SSRC selection prevents accidental replay of wrong media and removes ambiguity in mixed captures.

---

## 10. IPv4 / IPv6 Model

### Family source

- IP family is derived from `--local-ip` literal.
- This is the anchor for signaling/media socket binds and SDP family.

### Destination behavior

- `--host` may be DNS or literal.
- Runtime resolves host and connects SIP UDP client to resolved address.
- Operational requirement: choose destination address compatible with local bind family.

### Bind and SDP usage

- SIP UDP socket binds to `--local-ip`.
- RTP sender sockets bind to `--local-ip` (ephemeral local ports).
- SDP `o=`/`c=` lines advertise `--local-ip` and corresponding `IP4`/`IP6` family.

This keeps signaling, media sockets, and advertised addressing coherent.

---

## 11. Limitations (MVP)

Current scope intentionally excludes many SIP/media features:

- no SRTP,
- no ICE negotiation,
- no RTCP generation/handling,
- no re-INVITE,
- no UPDATE,
- no transcoding,
- no loop playback mode,
- no SIP over TCP/TLS (UDP only),
- no full SIP authentication framework (digest/auth flows are not part of baseline orchestration),
- no inbound call server mode.

This is a focused deterministic RTP replay tool, not a full SIP endpoint stack.

---

## 12. Design Decisions and Rationale

### Why PCAP as source

- PCAP contains complete packet-level truth (signaling + media timing).
- Avoids conversion pipelines and metadata loss common with specialized dump formats.
- Enables one artifact to reproduce end-to-end behavior.

### Why capture timestamp pacing (not RTP timestamp pacing)

- RTP clocks differ by codec and are not sufficient to reproduce observed wall-clock send behavior alone.
- Capture timing preserves actual packet burst/gap profile.

### Why a scheduler abstraction

- Central replay schedule makes timing model explicit and testable.
- Simplifies deterministic replay reasoning.
- Provides foundation for future features (looping, speed factor, jitter injection, slicing).

### Why outbound-only design

- Primary use case is active probe/call generation into existing infrastructure.
- Outbound-only reduces SIP state complexity and implementation risk.

### Why minimal SIP feature set

- Keeps reliability high for targeted test workflows.
- Avoids broad protocol-surface bugs unrelated to replay objective.
- Most tests require only INVITE/ACK/INFO-response/BYE lifecycle.

---

## 13. Common Pitfalls

### Wrong SSRC selection

Symptoms:

- no packets replayed,
- wrong codec/content,
- media mismatch against expected answer.

Mitigation:

- inspect PCAP SSRC inventory,
- verify selected SSRC exists and corresponds to intended direction.

### Mismatched SDP vs replayed RTP

Symptoms:

- far end rejects media,
- one-way/no media decode.

Mitigation:

- ensure selected SSRC stream payload types exist in generated offer and accepted answer.

### IPv6 DNS/address-family mismatch

Symptoms:

- bind/connect failures,
- no SIP responses.

Mitigation:

- ensure DNS returns compatible family or use explicit host literal that matches `--local-ip` family.

### Ignoring capture pacing

Symptoms:

- bursty/unnatural traffic,
- SBC/media jitter logic behaves differently from real case.

Mitigation:

- keep capture-time-based scheduling intact.

### Media rejected in SDP answer

Symptoms:

- no replay on one media type.

Mitigation:

- inspect 200 OK SDP `m=` lines/ports/formats,
- verify remote endpoint accepts offered payloads.

### NAT / incorrect local-ip

Symptoms:

- remote cannot return media,
- SIP works but RTP path fails.

Mitigation:

- bind/advertise the correct reachable local address for test topology.

---

## 14. Debugging Tips

### Logging and runtime checkpoints

- follow orchestrator logs for each phase:
  - CLI parse,
  - host resolution,
  - PCAP load,
  - SDP build,
  - INVITE/ACK,
  - replay start,
  - INFO handling,
  - BYE.

### SDP verification

- inspect generated offer:
  - local IP family/IP correctness,
  - payload types/rtpmap/fmtp presence.
- inspect parsed answer:
  - connection IP,
  - negotiated media ports and formats.

### RTP verification

- compare number of selected RTP packets vs packets sent.
- capture egress traffic with tcpdump/Wireshark.
- verify RTP headers (SSRC/PT/seq/timestamp/marker) match source stream.

### SIP wire validation

- check INVITE contains expected headers and SDP.
- ensure ACK transmitted after 200 OK.
- confirm INFO requests receive 200 OK.
- confirm BYE/200 termination.

### Tooling suggestions

- `tcpdump -ni <iface> udp and host <remote>` for packet path.
- Wireshark filters:
  - `sip`
  - `rtp.ssrc == 0x...`

---

## 15. Future Improvements

Potential extensions aligned with current architecture:

- **RTCP support**
  - send SR/RR and parse inbound control for realistic session behavior.

- **SIP auth support**
  - digest challenge handling for INVITE/BYE where required.

- **Loop playback / repeat mode**
  - continuous replay for soak/stability tests.

- **PCAP slicing and selection**
  - time-window and call-leg extraction before replay.

- **Replay controls**
  - speed factor, pause/resume, deterministic jitter injection.

- **Metrics/export**
  - packet counters, send latency histograms, failure counters.

- **Multiple concurrent calls**
  - orchestrate N dialogs with isolated stream maps and per-call metrics.

- **Address-family-aware target selection hardening**
  - enforce `--local-ip` family match during DNS resolution.

- **Transport/security expansion**
  - SIP over TCP/TLS and optional SRTP where test scenarios demand it.

---

## Operational Guardrails for Future AI Agents

When modifying `sip-tester`, preserve these invariants unless intentionally redesigning:

1. **Replay packets are sourced from PCAP RTP payloads, not generated media.**
2. **Timing model is capture-timestamp-based.**
3. **SSRC-driven stream selection remains explicit and deterministic.**
4. **SDP transport addresses are regenerated from runtime local IP/family, not copied from capture.**
5. **SIP control flow remains minimal and predictable (INVITE -> 200 -> ACK -> replay -> BYE).**
6. **IPv4/IPv6 behavior remains explicit, bind-driven, and testable.**

If a change violates any invariant, update this document and corresponding tests in the same change set.


## SIP authentication (INVITE only)

Digest authentication is optional and controlled by CLI credentials:

- If both `--username` and `--password` are provided, `sip-tester` handles a single Digest challenge for the initial outbound `INVITE`.
- Supported challenges:
  - `401 Unauthorized` with `WWW-Authenticate`
  - `407 Proxy Authentication Required` with `Proxy-Authenticate`
- For successful challenge handling, `sip-tester` retries `INVITE` once with:
  - `Authorization` for 401
  - `Proxy-Authorization` for 407

MVP limitations:

- INVITE digest auth only (no REGISTER/BYE/ACK auth)
- no cross-dialog auth caching
- `algorithm=MD5` (or omitted algorithm) only
- supports `qop=auth` or no `qop`
- `qop=auth-int` is unsupported
- no repeated auth loops beyond a single authenticated retry
