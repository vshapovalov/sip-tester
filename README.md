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
8. receive 200 OK
9. send ACK
10. start RTP replay
11. handle INFO
12. send BYE
13. exit
