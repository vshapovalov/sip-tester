package app

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type callDialog interface {
	dialogRequestHandler
	Bye(context.Context) error
}

func (s *runSetup) runEstablishedCall(dialog callDialog, reinviteAfter time.Duration, reinvite func(context.Context) error) (callError error) {
	requestContext, stopRequests := context.WithCancel(context.Background())
	requestDone := startDialogRequestLoop(requestContext, dialog, s.replayController.done, reinviteAfter, reinvite)
	defer func() {
		stopRequests()
		s.replayController.Stop()
		<-requestDone
		if replayError := s.replayController.Err(); replayError != nil && !errors.Is(callError, replayError) {
			callError = errors.Join(callError, fmt.Errorf("RTP replay: %w", replayError))
		}
	}()

	select {
	case result := <-requestDone:
		return result.err
	case <-s.replayController.done:
	}
	if err := s.replayController.Err(); err != nil {
		return fmt.Errorf("RTP replay: %w", err)
	}

	if s.cfg.HangupMode == "remote" {
		s.logger.Println("wait for remote BYE")
		timer := time.NewTimer(defaultStepTimeout)
		defer timer.Stop()
		select {
		case result := <-requestDone:
			return result.err
		case <-timer.C:
			return fmt.Errorf("wait for remote BYE: timed out after %s following RTP replay", defaultStepTimeout)
		}
	}

	// One goroutine owns SIP reads; finish it before waiting for our BYE response.
	stopRequests()
	result := <-requestDone
	if result.err != nil || result.method == "BYE" {
		return result.err
	}
	byeContext, cancelBye := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer cancelBye()
	s.logger.Println("send BYE")
	return dialog.Bye(byeContext)
}
