// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package secboot

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrReencryptionNoBackend = errors.New("no active backend")
)

type ReencryptionStatus int

const (
	ReencryptionStatusNone ReencryptionStatus = iota
	ReencryptionStatusInitialized
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

type ReencryptionProgressEventType int

const (
	ReencryptionProgressStarted ReencryptionProgressEventType = iota
	ReencryptionProgressRunning
	ReencryptionProgressCompleted
	ReencryptionProgressError
)

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
	BytesReencryptedSoFar    string `json:"device_bytes"`
	DeviceSize               string `json:"device_size"`
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

// ReencryptionForActiveVolume gets a handler for reencryption operations
// on the given active device mapper name.
func ReencryptionForActiveVolume(activeName string) (Reencryption, error) {
	for name, backend := range storageContainerHandlers {
		reencrypt, err := backend.NewOnlineReencryption(activeName)
		if err != nil {
			return nil, fmt.Errorf("cannot probe %q backend for active name %q: %w", name, activeName, err)
		}
		if reencrypt != nil {
			return reencrypt, nil
		}
		// Look for another registered backend
	}

	return nil, ErrReencryptionNoBackend
}
