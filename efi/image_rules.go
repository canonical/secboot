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
	"bytes"
	"crypto"
	"fmt"
)

type (
	newImageLoadHandlerFn func(peImageHandle) (imageLoadHandler, error)
)

// imagePredicate is used for testing image properties.
type imagePredicate interface {
	Matches(image peImageHandle) (bool, error)
}

type imagePredicateAny []imagePredicate

// imageMatchesAny returns a predicate that is satisfied if any of
// the supplied predicates are satisfied.
func imageMatchesAny(predicates ...imagePredicate) imagePredicate {
	return imagePredicateAny(predicates)
}

func (p imagePredicateAny) Matches(image peImageHandle) (bool, error) {
	for _, pred := range p {
		matches, err := pred.Matches(image)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

type imagePredicateAll []imagePredicate

// imageMatchesAll returns a predicate that is satisfied if all of
// the supplied predicates are satisfied.
func imageMatchesAll(predicates ...imagePredicate) imagePredicate {
	return imagePredicateAll(predicates)
}

func (p imagePredicateAll) Matches(image peImageHandle) (bool, error) {
	for _, pred := range p {
		matches, err := pred.Matches(image)
		if err != nil {
			return false, err
		}
		if !matches {
			return false, nil
		}
	}
	return true, nil
}

// imageRule is a single rule associated with a set of rules.
type imageRule struct {
	name   string
	match  imagePredicate
	create newImageLoadHandlerFn
}

// newImageRule returns a new imageRule with the supplied arguments.
func newImageRule(name string, match imagePredicate, create newImageLoadHandlerFn) *imageRule {
	return &imageRule{
		name:   name,
		match:  match,
		create: create,
	}
}

// imageRules is used to construct an imageLoadHandler from a peImageHandle
// using a set of rules.
type imageRules struct {
	name  string
	rules []*imageRule
}

func (r *imageRules) String() string {
	return r.name + " image rules"
}

// NewImageLoadHandler implements imageLoadHandlerConstructor
func (r *imageRules) NewImageLoadHandler(image peImageHandle) (imageLoadHandler, error) {
	for _, rule := range r.rules {
		matches, err := rule.match.Matches(image)
		if err != nil {
			return nil, fmt.Errorf("cannot run \"%s\" image rule: %w", rule.name, err)
		}
		if matches {
			handler, err := rule.create(image)
			if err != nil {
				return nil, fmt.Errorf("cannot create using \"%s\" image rule: %w", rule.name, err)
			}
			return handler, nil
		}
	}

	return nil, errNoHandler
}

func newImageRules(name string, rules ...*imageRule) *imageRules {
	return &imageRules{
		name:  name,
		rules: rules,
	}
}

type imageAlwaysMatchesPredicate struct{}

func (imageAlwaysMatchesPredicate) Matches(_ peImageHandle) (bool, error) {
	return true, nil
}

var imageAlwaysMatches = imageAlwaysMatchesPredicate{}

// imageSectionExists is a predicate that is satisfied if an image
// contains a section with the specified name.
type imageSectionExists string

func (p imageSectionExists) Matches(image peImageHandle) (bool, error) {
	return image.HasSection(string(p)), nil
}

// imageSignedByOrganization is a predicate that is satisfied if an
// image is signed by the specified organization.
type imageSignedByOrganization string

func (p imageSignedByOrganization) Matches(image peImageHandle) (bool, error) {
	sigs, err := image.SecureBootSignatures()
	if err != nil {
		return false, err
	}
	for _, sig := range sigs {
		signer := sig.GetSigner()
		if len(signer.Subject.Organization) > 0 && signer.Subject.Organization[0] == string(p) {
			return true, nil
		}
	}
	return false, nil
}

type imageDigestPredicate struct {
	alg    crypto.Hash
	digest []byte
}

func imageDigestMatches(alg crypto.Hash, digest []byte) imagePredicate {
	return &imageDigestPredicate{alg: alg, digest: digest}
}

func (p *imageDigestPredicate) Matches(image peImageHandle) (bool, error) {
	digest, err := image.ImageDigest(p.alg)
	if err != nil {
		return false, err
	}
	return bytes.Equal(digest, p.digest), nil
}

// sbatSectionExists is a predicate that is satisfied if an image has
// a .sbat section.
var sbatSectionExists imageSectionExists = ".sbat"

// sbatComponentExists is a predicate that is satisfied if an image has
// a SBAT component with the specicied name.
type sbatComponentExists string

func (p sbatComponentExists) Matches(image peImageHandle) (bool, error) {
	components, err := image.SbatComponents()
	if err != nil {
		return false, err
	}
	for _, c := range components {
		if c.Name == string(p) {
			return true, nil
		}
	}
	return false, nil
}

type shimVersionPredicate struct {
	operator string
	version  string
}

func shimVersionIs(operator, version string) imagePredicate {
	return &shimVersionPredicate{
		operator: operator,
		version:  version}
}

func (p *shimVersionPredicate) Matches(image peImageHandle) (bool, error) {
	shim := newShimImageHandle(image)
	x, err := shim.Version()
	if err != nil {
		return false, fmt.Errorf("cannot obtain shim version: %w", err)
	}

	y := mustParseShimVersion(p.version)

	res := x.Compare(y)
	switch p.operator {
	case ">":
		return res > 0, nil
	case ">=":
		return res >= 0, nil
	case "==":
		return res == 0, nil
	case "!=":
		return res != 0, nil
	case "<=":
		return res <= 0, nil
	case "<":
		return res < 0, nil
	default:
		return false, fmt.Errorf("invalid shim version operator %s", p.operator)
	}
}

type grubHasPrefix string

func (p grubHasPrefix) Matches(image peImageHandle) (bool, error) {
	grub := newGrubImageHandle(image)
	prefix, err := grub.Prefix()
	if err != nil {
		return false, fmt.Errorf("cannot obtain grub prefix: %w", err)
	}

	return prefix == string(p), nil
}
