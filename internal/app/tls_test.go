package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sip-tester/internal/config"
)

func TestLoadTLSConfigSkipsUnencryptedSignaling(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			tlsConfig, err := loadTLSConfig(&config.Config{Transport: transport, Host: "pbx.example.com"})
			if err != nil || tlsConfig != nil {
				t.Fatalf("TLS configuration=%v error=%v, want nil for %s", tlsConfig, err, transport)
			}
		})
	}
}

func TestLoadTLSConfigVerifiesServerByDefault(t *testing.T) {
	tlsConfig, err := loadTLSConfig(&config.Config{Transport: "tls", Host: "pbx.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig == nil {
		t.Fatal("missing TLS configuration")
	}
	if tlsConfig.ServerName != "pbx.example.com" || tlsConfig.MinVersion != tls.VersionTLS12 || tlsConfig.InsecureSkipVerify {
		t.Fatalf("TLS configuration does not enforce TLS 1.2+ with hostname verification: %+v", tlsConfig)
	}
	certificate, _ := tlsTestSelfSignedCertificate(t)
	_, err = certificate.Verify(x509.VerifyOptions{
		Roots: tlsConfig.RootCAs, DNSName: tlsConfig.ServerName, CurrentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("system trust unexpectedly accepted the private self-signed certificate")
	}
}

func TestLoadTLSConfigInsecureRequiresExplicitOptIn(t *testing.T) {
	tlsConfig, err := loadTLSConfig(&config.Config{Transport: "tls", Host: "pbx.example.com", TLSInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig == nil || !tlsConfig.InsecureSkipVerify || tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("insecure TLS configuration=%+v, want verification disabled with TLS 1.2+", tlsConfig)
	}
}

func TestLoadTLSConfigTrustsExplicitCAAndVerifiesHostname(t *testing.T) {
	certificate, certificatePEM := tlsTestSelfSignedCertificate(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := loadTLSConfig(&config.Config{Transport: "tls", Host: "pbx.example.com", TLSCAFile: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig == nil || tlsConfig.RootCAs == nil || tlsConfig.InsecureSkipVerify {
		t.Fatalf("TLS configuration=%+v, want explicit trust with verification enabled", tlsConfig)
	}
	verificationOptions := x509.VerifyOptions{
		Roots: tlsConfig.RootCAs, DNSName: tlsConfig.ServerName, CurrentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if _, err := certificate.Verify(verificationOptions); err != nil {
		t.Fatalf("explicit CA does not trust matching server certificate: %v", err)
	}
	verificationOptions.DNSName = "different.example.com"
	if _, err := certificate.Verify(verificationOptions); err == nil {
		t.Fatal("explicit CA incorrectly disables hostname verification")
	}
}

func TestLoadTLSConfigRejectsUnreadableCAFile(t *testing.T) {
	for _, caPath := range []string{filepath.Join(t.TempDir(), "missing.pem"), t.TempDir()} {
		tlsConfig, err := loadTLSConfig(&config.Config{Transport: "tls", Host: "pbx.example.com", TLSCAFile: caPath})
		if err == nil || !strings.Contains(err.Error(), "read TLS CA file") || tlsConfig != nil {
			t.Fatalf("CA path=%q configuration=%v error=%v, want CA read failure", caPath, tlsConfig, err)
		}
	}
}

func TestLoadTLSConfigRejectsInvalidCAFile(t *testing.T) {
	for _, certificatePEM := range []string{"", "not a PEM certificate", "-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"} {
		caPath := filepath.Join(t.TempDir(), "invalid.pem")
		if err := os.WriteFile(caPath, []byte(certificatePEM), 0600); err != nil {
			t.Fatal(err)
		}
		tlsConfig, err := loadTLSConfig(&config.Config{Transport: "tls", Host: "pbx.example.com", TLSCAFile: caPath})
		if err == nil || !strings.Contains(err.Error(), "no valid PEM certificates") || tlsConfig != nil {
			t.Fatalf("configuration=%v error=%v, want invalid CA failure", tlsConfig, err)
		}
	}
}

func tlsTestSelfSignedCertificate(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	certificateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"pbx.example.com"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}
