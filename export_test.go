// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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
	"io"
)

const (
	SanDirectoryNameTag = sanDirectoryNameTag
)

var (
	EkCertHandle = ekCertHandle
	EkHandle = ekHandle
	EkTemplate = ekTemplate
	OidExtensionSubjectAltName = oidExtensionSubjectAltName
	OidTcgAttributeTpmManufacturer = oidTcgAttributeTpmManufacturer
	OidTcgAttributeTpmModel = oidTcgAttributeTpmModel
	OidTcgAttributeTpmVersion = oidTcgAttributeTpmVersion
	OidTcgKpEkCertificate = oidTcgKpEkCertificate
)

func SetOpenDefaultTctiFn(fn func() (io.ReadWriteCloser, error)) {
	openDefaultTcti = fn
}

func InitTPMConnection(t *TPMConnection) error {
	return t.init()
}

func AppendRootCAHash(h []byte) {
	rootCAHashes = append(rootCAHashes, h)
}
