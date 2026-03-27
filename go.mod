module sip-tester

go 1.22

require (
	github.com/emiago/sipgo v0.0.0
	github.com/google/gopacket v0.0.0
)

replace github.com/google/gopacket => ./third_party/gopacket

replace github.com/emiago/sipgo => ./third_party/sipgo
