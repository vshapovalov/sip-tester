package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sip-tester/internal/replay"
)

type callDialog interface {
	dialogRequestHandler
	Bye(context.Context) error
}

func (s *runSetup) runEstablishedCall(dialog callDialog, reinviteAfter time.Duration, reinvite func(context.Context) error) (callError error) {
	requestContext, stopRequests := context.WithCancel(context.Background())
	finalVideoDone := s.startFinalVideoVerification(requestContext)
	requestDone := startDialogRequestLoop(requestContext, dialog, s.replayController.done, reinviteAfter, reinvite)
	var remoteHangupTimer *time.Timer
	defer func() {
		stopRequests()
		s.replayController.Stop()
		<-requestDone
		if finalVideoDone != nil {
			callError = errors.Join(callError, <-finalVideoDone)
		}
		if remoteHangupTimer != nil {
			remoteHangupTimer.Stop()
		}
		if replayError := s.replayController.Err(); replayError != nil && !errors.Is(callError, replayError) {
			callError = errors.Join(callError, fmt.Errorf("RTP replay: %w", replayError))
		}
	}()

	replayDone := s.replayController.done
	var remoteHangupTimeout <-chan time.Time
	for {
		select {
		case result := <-requestDone:
			return result.err
		case err := <-finalVideoDone:
			finalVideoDone = nil
			if err != nil {
				return err
			}
		case <-replayDone:
			replayDone = nil
			if err := s.replayController.Err(); err != nil {
				return fmt.Errorf("RTP replay: %w", err)
			}
			if s.cfg.HangupMode == "remote" {
				s.logger.Println("wait for remote BYE")
				remoteHangupTimer = time.NewTimer(defaultStepTimeout)
				remoteHangupTimeout = remoteHangupTimer.C
			}
		case <-remoteHangupTimeout:
			return fmt.Errorf("wait for remote BYE: timed out after %s following RTP replay", defaultStepTimeout)
		}
		isLocalHangupReady := replayDone == nil && finalVideoDone == nil && s.cfg.HangupMode != "remote"
		if isLocalHangupReady {
			break
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

// A nil channel means final video verification is disabled for this call.
func (s *runSetup) startFinalVideoVerification(ctx context.Context) <-chan error {
	if s.cfg.RequireFinalVideoPackets == 0 {
		return nil
	}
	videoConnection := s.transportStore.Get().Sockets.VideoConn
	done := make(chan error, 1)
	go func() {
		videoContext, cancelVideo := context.WithTimeout(ctx, defaultStepTimeout)
		defer cancelVideo()
		reception, err := replay.WaitForRTPPackets(videoContext, videoConnection, s.cfg.RequireFinalVideoPackets)
		if err != nil {
			done <- fmt.Errorf("verify final video RTP: %w", err)
			return
		}
		s.logger.Printf("final video RTP verified packets=%d first=%s last=%s", reception.PacketCount, reception.FirstPacketAt.UTC().Format(time.RFC3339Nano), reception.LastPacketAt.UTC().Format(time.RFC3339Nano))
		done <- nil
	}()
	return done
}
