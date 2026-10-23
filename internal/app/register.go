package app

import (
	"context"
	"fmt"
	"log"

	"sip-tester/internal/config"
	"sip-tester/internal/netutil"
)

func runRegister(cfg *config.Config, target netutil.ResolvedTarget, logger *log.Logger) error {
	client, err := createSIPClient(cfg, target, logger)
	if err != nil {
		return err
	}
	defer client.Close()

	contact, err := client.Contact(cfg.Caller)
	if err != nil {
		return fmt.Errorf("build REGISTER Contact: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer cancel()
	logger.Printf("send REGISTER requested-expires=%d", cfg.RegisterExpires)
	if err := client.Register(ctx, cfg.Caller, contact, cfg.RegisterExpires); err != nil {
		return err
	}
	logger.Printf("REGISTER succeeded status=200 requested-expires=%d", cfg.RegisterExpires)
	return nil
}
