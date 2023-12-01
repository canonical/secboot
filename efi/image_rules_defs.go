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

package efi

import (
	"crypto"
	"crypto/x509"
)

func makeMicrosoftUEFICASecureBootNamespaceRules() *secureBootNamespaceRules {
	return newSecureBootNamespaceRules(
		"Microsoft UEFI CA",
		withAuthority(
			// CN=Microsoft Corporation UEFI CA 2011,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US
			[]byte{
				0x30, 0x81, 0x81, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
				0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11,
				0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x57, 0x61, 0x73,
				0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30,
				0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65,
				0x64, 0x6d, 0x6f, 0x6e, 0x64, 0x31, 0x1e, 0x30, 0x1c, 0x06,
				0x03, 0x55, 0x04, 0x0a, 0x13, 0x15, 0x4d, 0x69, 0x63, 0x72,
				0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x43, 0x6f, 0x72, 0x70,
				0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x2b, 0x30,
				0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x4d, 0x69,
				0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x43, 0x6f,
				0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20,
				0x55, 0x45, 0x46, 0x49, 0x20, 0x43, 0x41, 0x20, 0x32, 0x30,
				0x31, 0x31,
			},
			// SKID
			[]byte{
				0x13, 0xad, 0xbf, 0x43, 0x09, 0xbd, 0x82, 0x70, 0x9c, 0x8c,
				0xd5, 0x4f, 0x31, 0x6e, 0xd5, 0x22, 0x98, 0x8a, 0x1b, 0xd4,
			},
			// pubkey alg
			x509.RSA,
		),
		withSelfSignedSignerOnlyForTesting(
			// O = Snake Oil
			[]byte{
				0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04,
				0x0a, 0x0c, 0x09, 0x53, 0x6e, 0x61, 0x6b, 0x65, 0x20, 0x4f,
				0x69, 0x6c,
			},
			// SKID
			[]byte{
				0x14, 0x3e, 0xce, 0x5d, 0xbd, 0x93, 0xea, 0xc3, 0xb2, 0xb1,
				0x1a, 0x37, 0x86, 0x3d, 0x9f, 0xd7, 0x94, 0x97, 0xf0, 0x8f,
			},
			// pubkey alg
			x509.RSA,
			// sig alg
			x509.SHA256WithRSA,
		),
		withImageRule(
			"SBAT-capable shim with .sbatlevel section",
			imageMatchesAll(
				sbatSectionExists,
				sbatComponentExists("shim"),
				imageSectionExists(".sbatlevel"),
			),
			newShimLoadHandler,
		),
		withImageRule(
			"SBAT-capable shim 15.6 without .sbatlevel section",
			imageMatchesAll(
				sbatSectionExists,
				sbatComponentExists("shim"),
				shimVersionIs("==", "15.6"),
			),
			newShimLoadHandlerConstructor().WithSbatLevel(shimSbatLevel{
				[]byte("sbat,1,2022052400\nshim,2\ngrub,2\n"),
				[]byte("sbat,1,2021030218\n")}).New,
		),
		withImageRule(
			"initial SBAT-capable shim",
			imageMatchesAll(
				sbatSectionExists,
				sbatComponentExists("shim"),
				shimVersionIs("<", "15.6"),
			),
			newShimLoadHandlerConstructor().WithSbatLevel(shimSbatLevel{
				[]byte("sbat,1,2021030218\n"),
				[]byte("sbat,1,2021030218\n")}).New,
		),
		// Pre SBAT shims - supported back to 15.2
		withImageRule(
			"pre SBAT shim",
			imageMatchesAll(
				imageSectionExists(".vendor_cert"),
				shimVersionIs(">=", "15.2"),
			),
			newShimLoadHandler,
		),
		// Ubuntu signed 2 shim 15's based on commit a4a1fbe with the required patches
		// backported. These were the initial UC20 shims
		withImageRule(
			"Ubuntu shim 15 with required patches",
			imageMatchesAll(
				imageSectionExists(".vendor_cert"),
				shimVersionIs("==", "15"),
				imageMatchesAny(
					// shim-signed_1.40.4+15+1552672080.a4a1fbe-0ubuntu2_amd64.deb
					imageDigestMatches(crypto.SHA256, []byte{
						0x2e, 0xa4, 0xcb, 0x6a, 0x1f, 0x1e, 0xb1, 0xd3,
						0xdc, 0xe8, 0x2d, 0x54, 0xfd, 0xe2, 0x6d, 0xed,
						0x24, 0x3b, 0xa3, 0xe1, 0x8d, 0xe7, 0xc6, 0xd2,
						0x11, 0x90, 0x2a, 0x59, 0x4f, 0xe5, 0x67, 0x88,
					}),
					// shim-signed_1.41+15+1552672080.a4a1fbe-0ubuntu1_amd64.deb
					imageDigestMatches(crypto.SHA256, []byte{
						0xe0, 0x60, 0xda, 0x09, 0x56, 0x1a, 0xe0, 0x0d,
						0xcf, 0xb1, 0x76, 0x9d, 0x6e, 0x8e, 0x84, 0x68,
						0x68, 0xa1, 0xe9, 0x9a, 0x54, 0xb1, 0x4a, 0xa5,
						0xd0, 0x68, 0x9f, 0x28, 0x40, 0xce, 0xc6, 0xdf,
					}),
				),
			),
			newShimLoadHandlerConstructor().WithVersion(mustParseShimVersion("15.2")).New,
		),
		withImageRuleOnlyForTesting(
			"Ubuntu shim 15 with required patches, signed with snakeoil key",
			imageMatchesAll(
				imageSectionExists(".vendor_cert"),
				shimVersionIs("==", "15"),
				imageSignedByOrganization("Snake Oil"),
			),
			newShimLoadHandlerConstructor().WithVersion(mustParseShimVersion("15.2")).New,
		),
		// Pre SBAT shims - unsupported. These will cause an error from
		// newShimLoadHandler rather than allowing this to fallback to the
		// null handler.
		withImageRule(
			"unsupported shim",
			imageSectionExists(".vendor_cert"),
			newShimLoadHandler,
		),
		// Ubuntu Grub with chainloader patch
		withImageRule(
			"Ubuntu grub",
			imageMatchesAny(
				imageMatchesAll(
					sbatSectionExists,
					sbatComponentExists("grub.ubuntu"),
				),
				imageMatchesAll(
					imageSectionExists("mods"),
					grubHasPrefix("/EFI/ubuntu"),
				),
			),
			newGrubLoadHandlerConstructor(grubChainloaderUsesShimProtocol).New,
		),
		withImageRule(
			"grub",
			imageMatchesAny(
				imageMatchesAll(
					sbatSectionExists,
					sbatComponentExists("grub"),
				),
				imageSectionExists("mods"),
			),
			newGrubLoadHandler,
		),
		withImageRule(
			"Ubuntu Core UKI",
			imageMatchesAny(
				imageMatchesAll(
					sbatSectionExists,
					sbatComponentExists("systemd.ubuntu"),
				),
				imageMatchesAll(
					// TODO: Add another primitive here to check the contents of the
					// .sdmagic section as an alternative to checking for the existence
					// of the .linux and .initrd sections.
					imageSectionExists(".linux"),
					imageSectionExists(".initrd"),
					imageSignedByOrganization("Canonical Ltd."),
				),
			),
			newUbuntuCoreUKILoadHandler,
		),
	)
}

func makeFallbackImageRules() *imageRules {
	return newImageRules(
		"Fallback",
		// Shim
		newImageRule(
			"shim",
			imageSectionExists(".vendor_cert"),
			newShimLoadHandler,
		),
		// Ubuntu grub
		newImageRule(
			"Ubuntu grub",
			imageMatchesAll(
				imageSectionExists("mods"),
				grubHasPrefix("/EFI/ubuntu"),
			),
			newGrubLoadHandlerConstructor(grubChainloaderUsesShimProtocol).New,
		),
		// Grub
		newImageRule(
			"grub",
			imageSectionExists("mods"),
			newGrubLoadHandler,
		),
		// TODO: add rules for Ubuntu Core UKIs that are not part of the MS UEFI CA
		//
		// Catch-all for unrecognized leaf images
		newImageRule(
			"null",
			imageAlwaysMatches,
			newNullLoadHandler,
		),
	)
}
