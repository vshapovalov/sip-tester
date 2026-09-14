package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"sip-tester/internal/config"
)

func loadTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Transport != "tls" {
		return nil, nil
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.TLSInsecure,
	}
	if cfg.TLSCAFile == "" {
		return tlsConfig, nil
	}
	certificatePEM, err := os.ReadFile(cfg.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA file %q: %w", cfg.TLSCAFile, err)
	}
	rootCertificates, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system TLS root certificates: %w", err)
	}
	if !rootCertificates.AppendCertsFromPEM(certificatePEM) {
		return nil, fmt.Errorf("TLS CA file %q contains no valid PEM certificates", cfg.TLSCAFile)
	}
	tlsConfig.RootCAs = rootCertificates
	return tlsConfig, nil
}
