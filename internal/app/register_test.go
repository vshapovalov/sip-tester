package app

import (
	"bufio"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

const registrationTestPassword = "registration-test-secret"

type registrationRunScenario struct {
	name            string
	expires         int
	expiryArgument  string
	challengeStatus int
	password        string
	finalStatus     int
	wantErrorStatus int
}

func TestRunRegisterCompletesOneTransactionWithoutMediaOrCalls(t *testing.T) {
	// Run captures process-wide stdout, so these scenarios must stay sequential.
	for _, transport := range []string{"udp", "tcp"} {
		for _, scenario := range []registrationRunScenario{
			{name: "default zero expiry", finalStatus: 200},
			{name: "positive expiry", expires: 60, expiryArgument: "60", finalStatus: 200},
			{name: "WWW Digest success", challengeStatus: 401, password: registrationTestPassword, finalStatus: 200},
			{name: "proxy Digest success", challengeStatus: 407, password: registrationTestPassword, finalStatus: 200},
			{name: "wrong password rejected", challengeStatus: 401, password: "incorrect-test-secret", finalStatus: 403, wantErrorStatus: 403},
			{name: "repeated challenge stops retrying", challengeStatus: 401, password: "incorrect-test-secret", finalStatus: 401, wantErrorStatus: 401},
			{name: "challenge without credentials", challengeStatus: 401, wantErrorStatus: 401},
		} {
			t.Run(transport+"/"+scenario.name, func(t *testing.T) {
				host, stopPeer, peerDone := startRunRegistrationPeer(t, transport, scenario)
				arguments := []string{"--mode", "register", "--caller", "registration-user", "--host", host, "--local-ip", "127.0.0.1", "--transport", transport}
				if scenario.expiryArgument != "" {
					arguments = append(arguments, "--register-expires", scenario.expiryArgument)
				}
				if scenario.password != "" {
					arguments = append(arguments, "--username", "registration-user", "--password", scenario.password)
				}

				started := time.Now()
				logs, runErr := runCapturingTransportLogs(t, arguments)
				elapsed := time.Since(started)
				isUnexpectedError := runErr != nil && (scenario.wantErrorStatus == 0 || !strings.Contains(runErr.Error(), strconv.Itoa(scenario.wantErrorStatus)))
				if isUnexpectedError {
					stopPeer()
				}
				peerErr := <-peerDone
				if scenario.wantErrorStatus == 0 {
					if runErr != nil {
						t.Fatalf("Run error=%v; peer error=%v\n%s", runErr, peerErr, logs)
					}
					if !strings.Contains(logs, "200") {
						t.Fatalf("successful registration did not report 200 OK: %s", logs)
					}
				} else if runErr == nil || !strings.Contains(runErr.Error(), strconv.Itoa(scenario.wantErrorStatus)) {
					t.Fatalf("Run error=%v, want registration status %d; peer error=%v", runErr, scenario.wantErrorStatus, peerErr)
				}
				if peerErr != nil {
					t.Fatal(peerErr)
				}
				if elapsed >= 2*time.Second {
					t.Fatalf("registration took %s; it must return without waiting for a call", elapsed)
				}
				if strings.Contains(logs, "load PCAP") || strings.Contains(logs, "INVITE") {
					t.Fatalf("registration entered call/media handling: %s", logs)
				}
				if strings.Contains(logs, registrationTestPassword) || strings.Contains(logs, "incorrect-test-secret") {
					t.Fatal("registration logged a password")
				}
			})
		}
	}
}

func TestRunRegisterReportsConfigurationFailuresWithoutMedia(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		arguments []string
		wantError string
	}{
		{
			name:      "empty caller AoR",
			arguments: []string{"--caller", "sip:"},
			wantError: "build REGISTER Contact",
		},
		{
			name:      "unreadable TLS CA",
			arguments: []string{"--caller", "registration-user", "--transport", "tls", "--tls-ca-file", filepath.Join(t.TempDir(), "missing-ca.pem")},
			wantError: "configure SIP TLS: read TLS CA file",
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			arguments := []string{"--mode", "register", "--host", "127.0.0.1:5060", "--local-ip", "127.0.0.1"}
			arguments = append(arguments, scenario.arguments...)
			logs, err := runCapturingTransportLogs(t, arguments)
			if err == nil || !strings.Contains(err.Error(), scenario.wantError) {
				t.Fatalf("Run error=%v, want %q", err, scenario.wantError)
			}
			if strings.Contains(logs, "load PCAP") || strings.Contains(logs, "send REGISTER") {
				t.Fatalf("registration configuration failure entered media handling or sent a request: %s", logs)
			}
		})
	}
}

func startRunRegistrationPeer(t *testing.T, transport string, scenario registrationRunScenario) (string, func(), <-chan error) {
	t.Helper()
	peerDone := make(chan error, 1)
	if transport == "udp" {
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		stop := func() { server.Close() }
		t.Cleanup(stop)
		go func() {
			var source *net.UDPAddr
			readRequest := func() (*sip.Request, net.Addr, error) {
				packet := make([]byte, 64*1024)
				length, sender, err := server.ReadFromUDP(packet)
				if err != nil {
					return nil, nil, err
				}
				source = sender
				request, _, err := sip.ParseMessage(packet[:length])
				if err == nil && request == nil {
					err = fmt.Errorf("received a SIP response instead of REGISTER")
				}
				return request, sender, err
			}
			writeResponse := func(response *sip.Response) error {
				_, err := server.WriteToUDP(sip.BuildResponse(response), source)
				return err
			}
			peerDone <- serveRunRegistration(readRequest, writeResponse, server.SetReadDeadline, transport, scenario)
		}()
		return server.LocalAddr().String(), stop, peerDone
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	stop := func() { listener.Close() }
	t.Cleanup(stop)
	if err := listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			peerDone <- fmt.Errorf("accept registration connection: %w", err)
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			peerDone <- err
			return
		}
		reader := bufio.NewReader(connection)
		readRequest := func() (*sip.Request, net.Addr, error) {
			request, err := readRunTransportRequest(reader)
			return request, connection.RemoteAddr(), err
		}
		writeResponse := func(response *sip.Response) error {
			_, err := connection.Write(sip.BuildResponse(response))
			return err
		}
		peerDone <- serveRunRegistration(readRequest, writeResponse, connection.SetReadDeadline, transport, scenario)
	}()
	return listener.Addr().String(), stop, peerDone
}

func serveRunRegistration(readRequest func() (*sip.Request, net.Addr, error), writeResponse func(*sip.Response) error, setReadDeadline func(time.Time) error, transport string, scenario registrationRunScenario) error {
	requestCount := 1
	if scenario.challengeStatus != 0 && scenario.password != "" {
		requestCount++
	}
	for requestIndex := 0; requestIndex < requestCount; requestIndex++ {
		if err := setReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return err
		}
		request, source, err := readRequest()
		if err != nil {
			return fmt.Errorf("read REGISTER %d: %w", requestIndex+1, err)
		}
		if err := validateRunRegistrationRequest(request, source, transport, scenario.expires); err != nil {
			return err
		}
		if requestIndex == 0 {
			if request.GetHeader("Authorization") != "" || request.GetHeader("Proxy-Authorization") != "" {
				return fmt.Errorf("initial REGISTER must be unauthenticated")
			}
		} else if err := validateRunRegistrationDigest(request, scenario); err != nil {
			return err
		}
		status := scenario.finalStatus
		if requestIndex == 0 && scenario.challengeStatus != 0 {
			status = scenario.challengeStatus
		}
		headers := make(map[string]string)
		for _, headerName := range []string{"Via", "From", "To", "Call-ID", "CSeq"} {
			headers[headerName] = request.GetHeader(headerName)
		}
		if status == 401 {
			headers["WWW-Authenticate"] = `Digest realm="registration-test", nonce="registration-nonce", algorithm=MD5, qop="auth"`
		} else if status == 407 {
			headers["Proxy-Authenticate"] = `Digest realm="registration-test", nonce="registration-nonce", algorithm=MD5, qop="auth"`
		}
		if err := writeResponse(&sip.Response{StatusCode: status, Reason: "Registration test response", Headers: headers}); err != nil {
			return fmt.Errorf("write REGISTER response: %w", err)
		}
	}
	if err := setReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return err
	}
	request, _, err := readRequest()
	if err == nil {
		return fmt.Errorf("unexpected request after %d REGISTER requests: %s", requestCount, request.Method)
	}
	var timeout net.Error
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.As(err, &timeout) && timeout.Timeout() {
		return nil
	}
	return fmt.Errorf("check for unexpected registration follow-up: %w", err)
}

func validateRunRegistrationRequest(request *sip.Request, source net.Addr, transport string, expires int) error {
	if request.Method != "REGISTER" {
		return fmt.Errorf("received %s, want REGISTER", request.Method)
	}
	host, _, err := net.SplitHostPort(source.String())
	if err != nil || !net.ParseIP(host).Equal(net.ParseIP("127.0.0.1")) {
		return fmt.Errorf("REGISTER source must be loopback: %s", source)
	}
	if request.Body != "" || request.GetHeader("Content-Length") != "0" {
		return fmt.Errorf("REGISTER must have an empty body")
	}
	if request.GetHeader("Expires") != strconv.Itoa(expires) {
		return fmt.Errorf("REGISTER Expires=%q, want %d", request.GetHeader("Expires"), expires)
	}
	if !strings.HasPrefix(request.GetHeader("Via"), "SIP/2.0/"+strings.ToUpper(transport)+" "+source.String()+";") {
		return fmt.Errorf("REGISTER Via does not identify its %s socket: %q", transport, request.GetHeader("Via"))
	}
	contact := strings.Trim(request.GetHeader("Contact"), "<>")
	contactURI, _, _ := strings.Cut(contact, ";")
	if contactURI != "sip:registration-user@"+source.String() {
		return fmt.Errorf("REGISTER Contact=%q, want concrete caller socket %s", contact, source)
	}
	if transport == "tcp" && !strings.Contains(contact, ";transport=tcp") {
		return fmt.Errorf("TCP REGISTER Contact lacks transport parameter: %q", contact)
	}
	return nil
}

func validateRunRegistrationDigest(request *sip.Request, scenario registrationRunScenario) error {
	headerName := "Authorization"
	otherHeaderName := "Proxy-Authorization"
	if scenario.challengeStatus == 407 {
		headerName, otherHeaderName = otherHeaderName, headerName
	}
	header := request.GetHeader(headerName)
	if !strings.HasPrefix(header, "Digest ") || request.GetHeader(otherHeaderName) != "" {
		return fmt.Errorf("REGISTER retry must have only %s Digest authentication", headerName)
	}
	parameters := make(map[string]string)
	for _, parameter := range strings.Split(strings.TrimPrefix(header, "Digest "), ",") {
		name, content, found := strings.Cut(strings.TrimSpace(parameter), "=")
		if !found {
			return fmt.Errorf("invalid Digest parameter")
		}
		parameters[name] = strings.Trim(content, `"`)
	}
	for parameter, expected := range map[string]string{
		"username": "registration-user", "realm": "registration-test", "nonce": "registration-nonce",
		"uri": request.URI, "algorithm": "MD5", "qop": "auth", "nc": "00000001",
	} {
		if parameters[parameter] != expected {
			return fmt.Errorf("Digest %s=%q, want %q", parameter, parameters[parameter], expected)
		}
	}
	if parameters["cnonce"] == "" {
		return fmt.Errorf("REGISTER Digest cnonce is missing")
	}
	responseForPassword := func(password string) string {
		ha1 := fmt.Sprintf("%x", md5.Sum([]byte("registration-user:registration-test:"+password)))
		ha2 := fmt.Sprintf("%x", md5.Sum([]byte("REGISTER:"+request.URI)))
		return fmt.Sprintf("%x", md5.Sum([]byte(ha1+":registration-nonce:00000001:"+parameters["cnonce"]+":auth:"+ha2)))
	}
	if parameters["response"] != responseForPassword(scenario.password) {
		return fmt.Errorf("REGISTER Digest response does not match method, URI, and test credentials")
	}
	if scenario.password != registrationTestPassword && parameters["response"] == responseForPassword(registrationTestPassword) {
		return fmt.Errorf("wrong password unexpectedly produced the accepted Digest response")
	}
	return nil
}
