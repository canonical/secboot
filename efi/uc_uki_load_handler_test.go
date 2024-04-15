// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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

package efi_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
)

type ucUkiLoadHandlerSuite struct{}

var _ = Suite(&ucUkiLoadHandlerSuite{})

type testUCUKIMeasureImageStartParams struct {
	alg    tpm2.HashAlgorithmId
	flags  PcrProfileFlags
	params LoadParams

	expectedEvents []*mockPcrBranchEvent
}

func (s *ucUkiLoadHandlerSuite) testMeasureImageStart(c *C, params *testUCUKIMeasureImageStartParams) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{alg: params.alg, flags: params.flags}, &params.params, nil)

	var handler UbuntuCoreUKILoadHandler
	c.Check(handler.MeasureImageStart(ctx), IsNil)
	c.Check(ctx.events, DeepEquals, params.expectedEvents)
}

func (s *ucUkiLoadHandlerSuite) TestMeasureImageStart(c *C) {
	s.testMeasureImageStart(c, &testUCUKIMeasureImageStartParams{
		alg:   tpm2.HashAlgorithmSHA256,
		flags: KernelConfigProfile,
		params: LoadParams{
			KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			SnapModel: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "2dc1d5c9791826cc681892421b14d36e5dd0241de367536f3ba5f7d9caa70e48")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "d64df514d7ac57c1a28c5f2a3abc39340d9b7fe3f76cc3acc991d418f095d5b0")},
		},
	})
}

func (s *ucUkiLoadHandlerSuite) TestMeasureImageStartDifferentCommandline(c *C) {
	s.testMeasureImageStart(c, &testUCUKIMeasureImageStartParams{
		alg:   tpm2.HashAlgorithmSHA256,
		flags: KernelConfigProfile,
		params: LoadParams{
			KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
			SnapModel: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "1295ed0b7ea5bf326d55223b446ebfeef10e487568dc0fee09edcce157c9c236")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "d64df514d7ac57c1a28c5f2a3abc39340d9b7fe3f76cc3acc991d418f095d5b0")},
		},
	})
}

func (s *ucUkiLoadHandlerSuite) TestMeasureImageStartDifferentModel(c *C) {
	s.testMeasureImageStart(c, &testUCUKIMeasureImageStartParams{
		alg:   tpm2.HashAlgorithmSHA256,
		flags: KernelConfigProfile,
		params: LoadParams{
			KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			SnapModel: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "other-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "2dc1d5c9791826cc681892421b14d36e5dd0241de367536f3ba5f7d9caa70e48")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "3be5bf8ae76a9eea01f016a69061ff2bf914b63a3b50436a3e997cc6e50393eb")},
		},
	})
}

func (s *ucUkiLoadHandlerSuite) TestMeasureImageStartNoKernelConfig(c *C) {
	s.testMeasureImageStart(c, &testUCUKIMeasureImageStartParams{
		alg: tpm2.HashAlgorithmSHA256,
		params: LoadParams{
			KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			SnapModel: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
	})
}

func (s *ucUkiLoadHandlerSuite) TestMeasureImageStartSHA1(c *C) {
	s.testMeasureImageStart(c, &testUCUKIMeasureImageStartParams{
		alg:   tpm2.HashAlgorithmSHA1,
		flags: KernelConfigProfile,
		params: LoadParams{
			KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
			SnapModel: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "f4e8b2c40f233509dce97fe70d20a474e8a3ec7e")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "9069ca78e7450a285173431b3e52c5c25299e473")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "28be03fcfc8de01cbf2237a3c41d22ffa81bee2f")},
		},
	})
}

func (s *ucUkiLoadHandlerSuite) TestMeasureImageStartNoCommandline(c *C) {
	s.testMeasureImageStart(c, &testUCUKIMeasureImageStartParams{
		alg:   tpm2.HashAlgorithmSHA256,
		flags: KernelConfigProfile,
		params: LoadParams{
			SnapModel: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
				"authority-id": "fake-brand",
				"series":       "16",
				"brand-id":     "fake-brand",
				"model":        "fake-model",
				"grade":        "secured",
			}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		},
		expectedEvents: []*mockPcrBranchEvent{
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")},
			{pcr: 12, eventType: mockPcrBranchExtendEvent, digest: testutil.DecodeHexString(c, "d64df514d7ac57c1a28c5f2a3abc39340d9b7fe3f76cc3acc991d418f095d5b0")},
		},
	})
}

func (s *ucUkiLoadHandlerSuite) TestMeasureImageStartNoSnapModel(c *C) {
	ctx := newMockPcrBranchContext(&mockPcrProfileContext{alg: tpm2.HashAlgorithmSHA256, flags: KernelConfigProfile}, nil, nil)

	var handler UbuntuCoreUKILoadHandler
	c.Check(handler.MeasureImageStart(ctx), ErrorMatches, `snap model must be set using SnapModelParams`)
}
