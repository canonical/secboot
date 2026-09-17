package secboot

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrReencryptionNotActive = errors.New("not active")
)

type ReencryptionStatus int

const (
	ReencryptionStatusNone ReencryptionStatus = iota
	ReencryptionStatusInitialized
)

type ReencryptionProgressEventType int

const (
	ReencryptionProgressStarted ReencryptionProgressEventType = iota
	ReencryptionProgressRunning
	ReencryptionProgressCompleted
	ReencryptionProgressError
)

func (r ReencryptionStatus) String() string {
	switch r {
	case ReencryptionStatusNone:
		return "none"
	case ReencryptionStatusInitialized:
		return "initialized"
	default:
		return fmt.Sprintf("unknown-%d", int(r))
	}
}

func (r ReencryptionProgressEventType) String() string {
	switch r {
	case ReencryptionProgressStarted:
		return "started"
	case ReencryptionProgressRunning:
		return "running"
	case ReencryptionProgressCompleted:
		return "completed"
	case ReencryptionProgressError:
		return "error"
	default:
		return fmt.Sprintf("unknown-%d", int(r))
	}
}

type ReencryptionProgressDetails struct {
	// "device" (which gives the path to the LUKS device) omitted because not relevant here
	DeviceSize               string `json:"device_size"`
	BytesReencryptedSoFar    string `json:"device_bytes"`
	CalculatedSpeed          string `json:"speed"`
	EstimatedTimeRemainingMs string `json:"eta_ms"`
	TotalTimeSoFarMs         string `json:"time_ms"`
}

type ReencryptionProgressEvent struct {
	Type ReencryptionProgressEventType

	Details ReencryptionProgressDetails

	// Error is fulfilled when:
	// - Type is ReencryptionProgressRunning but Details cannot be obtained
	// - Type is ReencryptionProgressError
	Error error
}

type Reencryption interface {
	Status() (*ReencryptionStatus, error)
	Initialize(ctx context.Context, unlockKeys map[string][]byte) error
	Resume(ctx context.Context, unlockKey []byte) (<-chan ReencryptionProgressEvent, error)
}

func ReencryptionForActiveVolume(activeName string) (Reencryption, error) {
	for name, backend := range storageContainerHandlers {
		reencrypt, err := backend.NewOnlineReencryption(activeName)
		if err != nil {
			return nil, fmt.Errorf("cannot probe %q backend for active name %q: %w", name, activeName, err)
		}
		if reencrypt != nil {
			return reencrypt, nil
		}
	}

	return nil, ErrReencryptionNotActive
}
