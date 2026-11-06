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

	// ActiveName returns the name of the online encrypted container.
	ActiveName() string

	// Initialize creates the new encryption keys on the underlying backend device.
	//
	// All the unlock keys of the storage container must be provided
	// (the key of the map shall be the keyslot name).
	Initialize(ctx context.Context, unlockKeys map[string][]byte) error

	// Resume starts reencrypting the blocks of the underlying backend device
	// with the new encryption keys.
	//
	// This is done asynchronously, and the caller of this function must read all values
	// from the channel up to the final ReencryptionProgressEvent to free all resources.
	// The [ReencryptionProgressEvent.Type] of the values conveyed through the channel are
	// in this order:
	// - [ReencryptionProgressStarted], exactly once
	// - [ReencryptionProgressRunning], zero, one or multiple times
	// - [ReencryptionProgressCompleted] or [ReencryptionProgressError], exactly once
	Resume(ctx context.Context, unlockKey []byte) (<-chan ReencryptionProgressEvent, error)

	// Status gets the status of reencryption on the underlying backend device.
	Status() (*ReencryptionStatus, error)
}

// ReencryptionForActiveVolume gets a handler for reencryption operations
// on the given active device mapper name.
func ReencryptionForActiveVolume(activeName string) (Reencryption, error) {
	for name, backend := range storageContainerHandlers {
		reencrypt, err := backend.NewOnlineReencryption(activeName)
		if err != nil {
			// This backend is supposed to handle this active name, but there is an error
			return nil, fmt.Errorf("cannot probe %q backend for active name %q: %w", name, activeName, err)
		}
		if reencrypt != nil {
			return reencrypt, nil
		}
		// This backend is not supposed to handle this active name
		// Look for another registered backend
	}

	return nil, ErrReencryptionNoBackend
}
