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

package tpm2_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/hkdf"
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"
	internal_crypto "github.com/snapcore/secboot/internal/crypto"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type lockoutauthSuiteMixin struct{}

func (*lockoutauthSuiteMixin) newDefaultLockoutAuthPolicy(c *C, alg tpm2.HashAlgorithmId) (tpm2.Digest, *policyutil.Policy) {
	builder := policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().AddBranchNode(func(n *policyutil.PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.AddBranchNode(func(n *policyutil.PolicyBuilderBranchNode) {
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandDictionaryAttackLockReset)
				})
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandDictionaryAttackParameters)
				})
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandClearControl)
				})
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandClear)
				})

				// XXX: This is here temporarily to make provisioningSuite.TestProvisionWithLockoutAuthData
				// pass and will be removed in the next PR.
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth)
				})
			})
			b.PolicyAuthValue()
		})
	})

	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	return digest, policy
}

func (*lockoutauthSuiteMixin) newRotateAuthValueLockoutAuthPolicy(c *C, alg tpm2.HashAlgorithmId, oldAuthValue []byte) (tpm2.Digest, *policyutil.Policy) {
	r := hkdf.Expand(alg.NewHash, oldAuthValue, []byte("CHANGE-AUTH"))
	key, err := internal_crypto.GenerateECDSAKey(elliptic.P256(), r)
	c.Assert(err, IsNil)
	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := policyutil.NewPolicyBuilder(alg)
	builder.RootBranch().AddBranchNode(func(n *policyutil.PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.AddBranchNode(func(n *policyutil.PolicyBuilderBranchNode) {
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandDictionaryAttackLockReset)
				})
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandDictionaryAttackParameters)
				})
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandClearControl)
				})
				n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandClear)
				})
			})
			b.PolicyAuthValue()
		})
		n.AddBranch("", func(b *policyutil.PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth)
			b.PolicySigned(pubKey, []byte("CHANGE-AUTH"))
		})
	})

	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	return digest, policy
}

func (*lockoutauthSuiteMixin) makeLockoutAuthData(c *C, params *LockoutAuthParams) []byte {
	data, err := json.Marshal(params)
	c.Assert(err, IsNil)
	return data
}

func (m *lockoutauthSuiteMixin) makeDefaultLockoutAuthData(c *C, alg tpm2.HashAlgorithmId, val []byte) (tpm2.Digest, []byte) {
	digest, policy := m.newDefaultLockoutAuthPolicy(c, alg)
	return digest, m.makeLockoutAuthData(c, &LockoutAuthParams{
		AuthValue:  val,
		AuthPolicy: policy,
	})
}

type lockoutauthSuiteNoTPM struct {
	lockoutauthSuiteMixin
}

func (s *lockoutauthSuiteNoTPM) newDefaultLockoutAuthPolicy(c *C, alg tpm2.HashAlgorithmId) *policyutil.Policy {
	_, policy := s.lockoutauthSuiteMixin.newDefaultLockoutAuthPolicy(c, alg)
	return policy
}

func (s *lockoutauthSuiteNoTPM) newRotateAuthValueLockoutAuthPolicy(c *C, alg tpm2.HashAlgorithmId, oldAuthValue []byte) *policyutil.Policy {
	_, policy := s.lockoutauthSuiteMixin.newRotateAuthValueLockoutAuthPolicy(c, alg, oldAuthValue)
	return policy
}

type lockoutauthSuite struct {
	tpm2test.TPMTest
	lockoutauthSuiteMixin
}

func (s *lockoutauthSuite) SetUpSuite(c *C) {
	s.TPMFeatures = tpm2test.TPMFeatureLockoutHierarchy |
		tpm2test.TPMFeaturePlatformHierarchy |
		tpm2test.TPMFeatureClear |
		tpm2test.TPMFeatureNV
}

func (s *lockoutauthSuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)

	c.Assert(s.TPM().DictionaryAttackParameters(s.TPM().LockoutHandleContext(), 32, 7200, 86400, nil), IsNil)
}

var _ = Suite(&lockoutauthSuiteNoTPM{})
var _ = Suite(&lockoutauthSuite{})

func (s *lockoutauthSuiteNoTPM) TestLockoutAuthParamsMarshalJSON(c *C) {
	params := &LockoutAuthParams{
		AuthValue:  testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1"),
		AuthPolicy: s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256),
	}

	data, err := json.Marshal(params)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AAAAAAAAAAEAC5xRENPNjPxvymnylptEkkmB67kMJSALrpC4PA2joYWCAAAAAAAAAAEgAQFxAAAAAQAAAAAAAQAL+21OPQovgBAFA+/1biwvpZu8ItTlnZBiGL/DKXTgoIIAAAACIAEBcQAAAAQAAAAAAAEAC7bFwF5YGQnN6n33pfkcDy7tN/128VUi7uW1X4lvLVY/AAAAAQAAAWwAAAE5AAAAAAABAAscaCd8nWVk3YG8z35Wuj7cqziPxgzpWzpEK9JyWPYN/AAAAAEAAAFsAAABOgAAAAAAAQALlAz7Qhe7Htz3+0GTfKl0qmjmmKt4uBJLBwET4hH9RvwAAAABAAABbAAAAScAAAAAAAEAC8Tfq87ajeg2yVZhlSiSsd73IDr7Rv7+xD/8/JO+VAcwAAAAAQAAAWwAAAEmAAABaw=="}`))
}

func (s *lockoutauthSuiteNoTPM) TestLockoutAuthParamsMarshalJSONNoPolicy(c *C) {
	params := &LockoutAuthParams{
		AuthValue: testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1"),
	}

	data, err := json.Marshal(params)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE="}`))
}

func (s *lockoutauthSuiteNoTPM) TestLockoutAuthParamsMarshalJSONForChangeAuth(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	params := &LockoutAuthParams{
		AuthValue:     authValue,
		AuthPolicy:    s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256),
		NewAuthValue:  testutil.DecodeHexString(c, "db82cbebd10ebd831b48ff8ae7275a23029074ba622c0416d97cd34dd38d8186"),
		NewAuthPolicy: s.newRotateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, authValue),
	}

	data, err := json.Marshal(params)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AAAAAAAAAAEAC5xRENPNjPxvymnylptEkkmB67kMJSALrpC4PA2joYWCAAAAAAAAAAEgAQFxAAAAAQAAAAAAAQAL+21OPQovgBAFA+/1biwvpZu8ItTlnZBiGL/DKXTgoIIAAAACIAEBcQAAAAQAAAAAAAEAC7bFwF5YGQnN6n33pfkcDy7tN/128VUi7uW1X4lvLVY/AAAAAQAAAWwAAAE5AAAAAAABAAscaCd8nWVk3YG8z35Wuj7cqziPxgzpWzpEK9JyWPYN/AAAAAEAAAFsAAABOgAAAAAAAQALlAz7Qhe7Htz3+0GTfKl0qmjmmKt4uBJLBwET4hH9RvwAAAABAAABbAAAAScAAAAAAAEAC8Tfq87ajeg2yVZhlSiSsd73IDr7Rv7+xD/8/JO+VAcwAAAAAQAAAWwAAAEmAAABaw==","new-auth-value":"24LL69EOvYMbSP+K5ydaIwKQdLpiLAQW2XzTTdONgYY=","new-auth-policy":"AAAAAAAAAAEAC8iuOzJsfCEvz5HdnLSO98fhopBFpLgo9fX7/1TF/6KqAAAAAAAAAAEgAQFxAAAAAgAAAAAAAQAL+21OPQovgBAFA+/1biwvpZu8ItTlnZBiGL/DKXTgoIIAAAACIAEBcQAAAAQAAAAAAAEAC7bFwF5YGQnN6n33pfkcDy7tN/128VUi7uW1X4lvLVY/AAAAAQAAAWwAAAE5AAAAAAABAAscaCd8nWVk3YG8z35Wuj7cqziPxgzpWzpEK9JyWPYN/AAAAAEAAAFsAAABOgAAAAAAAQALlAz7Qhe7Htz3+0GTfKl0qmjmmKt4uBJLBwET4hH9RvwAAAABAAABbAAAAScAAAAAAAEAC8Tfq87ajeg2yVZhlSiSsd73IDr7Rv7+xD/8/JO+VAcwAAAAAQAAAWwAAAEmAAABawAAAAAAAQALDDnMvDFtHshfTn3M6F3KHOta8q5u4GWsqsqB8JnLJCYAAAACAAABbAAAASkAAAFgACMACwAEAAAAAAAQABAAAwAQACC2BaF5zNUOUWsO9Vxdw5PNDslawcvHjS3x54a1VHxZfAAgaOCKN2rpEFpajypuc/XSGSr0LnK/e8W9IyZMM8DufpUAC0NIQU5HRS1BVVRIAAAAAAAA"}`))
}

func (s *lockoutauthSuiteNoTPM) TestLockoutAuthParamsUnmarshalJSON(c *C) {
	data := []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AAAAAAAAAAEAC5xRENPNjPxvymnylptEkkmB67kMJSALrpC4PA2joYWCAAAAAAAAAAEgAQFxAAAAAQAAAAAAAQAL+21OPQovgBAFA+/1biwvpZu8ItTlnZBiGL/DKXTgoIIAAAACIAEBcQAAAAQAAAAAAAEAC7bFwF5YGQnN6n33pfkcDy7tN/128VUi7uW1X4lvLVY/AAAAAQAAAWwAAAE5AAAAAAABAAscaCd8nWVk3YG8z35Wuj7cqziPxgzpWzpEK9JyWPYN/AAAAAEAAAFsAAABOgAAAAAAAQALlAz7Qhe7Htz3+0GTfKl0qmjmmKt4uBJLBwET4hH9RvwAAAABAAABbAAAAScAAAAAAAEAC8Tfq87ajeg2yVZhlSiSsd73IDr7Rv7+xD/8/JO+VAcwAAAAAQAAAWwAAAEmAAABaw=="}`)

	expected := &LockoutAuthParams{
		AuthValue:  testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1"),
		AuthPolicy: s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256),
	}

	var params *LockoutAuthParams
	c.Assert(json.Unmarshal(data, &params), IsNil)
	c.Check(params, DeepEquals, expected)
}

func (s *lockoutauthSuiteNoTPM) TestLockoutAuthParamsUnmarshalJSONForChangeAuth(c *C) {
	data := []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AAAAAAAAAAEAC5xRENPNjPxvymnylptEkkmB67kMJSALrpC4PA2joYWCAAAAAAAAAAEgAQFxAAAAAQAAAAAAAQAL+21OPQovgBAFA+/1biwvpZu8ItTlnZBiGL/DKXTgoIIAAAACIAEBcQAAAAQAAAAAAAEAC7bFwF5YGQnN6n33pfkcDy7tN/128VUi7uW1X4lvLVY/AAAAAQAAAWwAAAE5AAAAAAABAAscaCd8nWVk3YG8z35Wuj7cqziPxgzpWzpEK9JyWPYN/AAAAAEAAAFsAAABOgAAAAAAAQALlAz7Qhe7Htz3+0GTfKl0qmjmmKt4uBJLBwET4hH9RvwAAAABAAABbAAAAScAAAAAAAEAC8Tfq87ajeg2yVZhlSiSsd73IDr7Rv7+xD/8/JO+VAcwAAAAAQAAAWwAAAEmAAABaw==","new-auth-value":"24LL69EOvYMbSP+K5ydaIwKQdLpiLAQW2XzTTdONgYY=","new-auth-policy":"AAAAAAAAAAEAC8iuOzJsfCEvz5HdnLSO98fhopBFpLgo9fX7/1TF/6KqAAAAAAAAAAEgAQFxAAAAAgAAAAAAAQAL+21OPQovgBAFA+/1biwvpZu8ItTlnZBiGL/DKXTgoIIAAAACIAEBcQAAAAQAAAAAAAEAC7bFwF5YGQnN6n33pfkcDy7tN/128VUi7uW1X4lvLVY/AAAAAQAAAWwAAAE5AAAAAAABAAscaCd8nWVk3YG8z35Wuj7cqziPxgzpWzpEK9JyWPYN/AAAAAEAAAFsAAABOgAAAAAAAQALlAz7Qhe7Htz3+0GTfKl0qmjmmKt4uBJLBwET4hH9RvwAAAABAAABbAAAAScAAAAAAAEAC8Tfq87ajeg2yVZhlSiSsd73IDr7Rv7+xD/8/JO+VAcwAAAAAQAAAWwAAAEmAAABawAAAAAAAQALDDnMvDFtHshfTn3M6F3KHOta8q5u4GWsqsqB8JnLJCYAAAACAAABbAAAASkAAAFgACMACwAEAAAAAAAQABAAAwAQACC2BaF5zNUOUWsO9Vxdw5PNDslawcvHjS3x54a1VHxZfAAgaOCKN2rpEFpajypuc/XSGSr0LnK/e8W9IyZMM8DufpUAC0NIQU5HRS1BVVRIAAAAAAAA"}`)

	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	expected := &LockoutAuthParams{
		AuthValue:     authValue,
		AuthPolicy:    s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256),
		NewAuthValue:  testutil.DecodeHexString(c, "db82cbebd10ebd831b48ff8ae7275a23029074ba622c0416d97cd34dd38d8186"),
		NewAuthPolicy: s.newRotateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, authValue),
	}

	var params *LockoutAuthParams
	c.Assert(json.Unmarshal(data, &params), IsNil)
	c.Check(params, DeepEquals, expected)
}

func (s *lockoutauthSuiteNoTPM) TestLockoutAuthParamsUnmarshalJSONInvalidAuthPolicy(c *C) {
	data := []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AA=="}`)

	var params *LockoutAuthParams
	c.Assert(json.Unmarshal(data, &params), ErrorMatches, `cannot decode auth-policy: cannot unmarshal argument 0 whilst processing element of type uint32: unexpected EOF

=== BEGIN STACK ===
\.\.\. policyutil\.Policy location .+\.go:[0-9]+, argument 0
=== END STACK ===
`)
}

type testResetDictionaryAttackLockParams struct {
	authValue    tpm2.Auth
	policyDigest tpm2.Digest
	policyAlg    tpm2.HashAlgorithmId
	prepare      func()
	data         []byte
}

func (s *lockoutauthSuite) testResetDictionaryAttackLock(c *C, params *testResetDictionaryAttackLockParams) error {
	// Setup hierarchy authorization
	// XXX: A subequent PR will make EnsureProvisioned do this instead
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, params.authValue)
	c.Assert(s.TPM().SetPrimaryPolicy(s.TPM().LockoutHandleContext(), params.policyDigest, params.policyAlg, nil), IsNil)
	s.TPM().LockoutHandleContext().SetAuthValue(nil) // Make sure ResetDictionaryAttackLock sets this.

	// Increment the DA counter by 1
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
	c.Assert(err, IsNil)
	key, err := s.TPM().LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
	key.SetAuthValue(nil)
	_, err = s.TPM().Unseal(key, nil)
	c.Assert(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)

	// Check the DA counter
	val, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutCounter)
	c.Assert(err, IsNil)
	c.Assert(val, Equals, uint32(1))

	if params.prepare != nil {
		params.prepare()
	}

	resetErr := s.TPM().ResetDictionaryAttackLock(params.data)
	if resetErr != nil && !errors.Is(resetErr, ErrEmptyLockoutAuthValue) {
		return resetErr
	}

	val, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutCounter)
	c.Assert(err, IsNil)
	c.Assert(val, Equals, uint32(0))

	c.Check(s.TPM().LockoutHandleContext().AuthValue(), DeepEquals, []byte(nil))

	return resetErr
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLock(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	digest, policy := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		authValue:    authValue,
		policyDigest: digest,
		policyAlg:    tpm2.HashAlgorithmSHA256,
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthValue:  authValue,
			AuthPolicy: policy,
		}),
	})
	c.Check(err, IsNil)

	cmds := s.CommandLog()
	c.Assert(len(cmds) > 2, testutil.IsTrue)
	cmd := cmds[len(cmds)-3]
	c.Check(cmd.CmdCode, Equals, tpm2.CommandDictionaryAttackLockReset)
	c.Assert(cmd.CmdAuthArea, HasLen, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle.Type(), Equals, tpm2.HandleTypePolicySession)

	c.Check(s.TPM().DoesHandleExist(cmd.CmdAuthArea[0].SessionHandle), testutil.IsFalse)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockAuthValueUnset(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	digest, policy := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		policyDigest: digest,
		policyAlg:    tpm2.HashAlgorithmSHA256,
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthValue:  authValue,
			AuthPolicy: policy,
		}),
	})
	c.Check(err, ErrorMatches, `the authorization value for the lockout hierarchy is empty`)
	c.Check(err, Equals, ErrEmptyLockoutAuthValue)

	cmds := s.CommandLog()
	c.Assert(len(cmds) > 2, testutil.IsTrue)
	cmd := cmds[len(cmds)-3]
	c.Check(cmd.CmdCode, Equals, tpm2.CommandDictionaryAttackLockReset)
	c.Assert(cmd.CmdAuthArea, HasLen, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle.Type(), Equals, tpm2.HandleTypePolicySession)

	c.Check(s.TPM().DoesHandleExist(cmd.CmdAuthArea[0].SessionHandle), testutil.IsFalse)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockWithAuthValue(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")

	// Setup hierarchy authorization
	// XXX: A subequent PR will make EnsureProvisioned do this instead
	s.HierarchyChangeAuth(c, tpm2.HandleLockout, authValue)
	s.TPM().LockoutHandleContext().SetAuthValue(nil) // Make sure ResetDictionaryAttackLock sets this.

	// Increment the DA counter by 1
	pub, sensitive, err := objectutil.NewSealedObject(rand.Reader, []byte("foo"), []byte("5678"))
	c.Assert(err, IsNil)
	key, err := s.TPM().LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
	key.SetAuthValue(nil)
	_, err = s.TPM().Unseal(key, nil)
	c.Assert(tpm2.IsTPMSessionError(err, tpm2.ErrorAuthFail, tpm2.CommandUnseal, 1), testutil.IsTrue)

	// Check the DA counter
	val, err := s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutCounter)
	c.Assert(err, IsNil)
	c.Assert(val, Equals, uint32(1))

	c.Check(s.TPM().ResetDictionaryAttackLockWithAuthValue(authValue), IsNil)

	val, err = s.TPM().GetCapabilityTPMProperty(tpm2.PropertyLockoutCounter)
	c.Assert(err, IsNil)
	c.Assert(val, Equals, uint32(0))

	c.Check(s.TPM().LockoutHandleContext().AuthValue(), DeepEquals, []byte(nil))

	cmds := s.CommandLog()
	for _, cmd := range cmds {
		c.Logf("%v", cmd.CmdCode)
	}
	c.Assert(len(cmds) > 1, testutil.IsTrue)
	cmd := cmds[len(cmds)-2]
	c.Check(cmd.CmdCode, Equals, tpm2.CommandDictionaryAttackLockReset)
	c.Assert(cmd.CmdAuthArea, HasLen, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, s.TPM().HmacSession().Handle())

	c.Check(s.TPM().DoesHandleExist(s.TPM().HmacSession().Handle()), testutil.IsTrue)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockInvalidData(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	digest, _ := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		authValue:    authValue,
		policyDigest: digest,
		policyAlg:    tpm2.HashAlgorithmSHA256,
		data:         []byte(`foo`),
	})
	c.Check(err, ErrorMatches, `invalid lockout hierarchy authorization data: invalid character 'o' in literal false \(expecting 'a'\)`)
	c.Check(err, testutil.ConvertibleTo, &InvalidLockoutAuthDataError{})
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockUnsupportedAuthValueRotation(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	digest, policy := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		authValue:    authValue,
		policyDigest: digest,
		policyAlg:    tpm2.HashAlgorithmSHA256,
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthValue:    authValue,
			AuthPolicy:   policy,
			NewAuthValue: testutil.DecodeHexString(c, "db82cbebd10ebd831b48ff8ae7275a23029074ba622c0416d97cd34dd38d8186"),
		}),
	})
	c.Check(err, ErrorMatches, `lockout hierarchy auth value change not supported yet`)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockAuthFail(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	digest, policy := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	defer s.ClearTPMUsingPlatformHierarchy(c)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		authValue:    authValue,
		policyDigest: digest,
		policyAlg:    tpm2.HashAlgorithmSHA256,
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthPolicy: policy,
		}),
	})
	c.Check(err, ErrorMatches, `cannot access resource at handle TPM_RH_LOCKOUT because an authorization check failed`)
	c.Assert(err, testutil.ConvertibleTo, AuthFailError{})
	c.Check(err.(AuthFailError).Handle, Equals, tpm2.HandleLockout)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockLockout(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	digest, policy := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	defer s.ClearTPMUsingPlatformHierarchy(c)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		authValue:    authValue,
		policyDigest: digest,
		policyAlg:    tpm2.HashAlgorithmSHA256,
		prepare: func() {
			c.Check(s.TPM().HierarchyChangeAuth(s.TPM().LockoutHandleContext(), nil, nil), testutil.ErrorIs,
				&tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandHierarchyChangeAuth, Code: tpm2.ErrorAuthFail}, Index: 1})
		},
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthValue:  authValue,
			AuthPolicy: policy,
		}),
	})
	c.Check(err, ErrorMatches, `the TPM is in DA lockout mode`)
	c.Check(err, Equals, ErrTPMLockout)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockInvalidPolicy(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	_, policy := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		authValue:    authValue,
		policyDigest: testutil.DecodeHexString(c, "5e517fa9d3184d1b37338b34a0a8aa4fb8f4c74cdde8cade3ba4357d31af7b7c"),
		policyAlg:    tpm2.HashAlgorithmSHA256,
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthPolicy: policy,
		}),
	})
	c.Check(err, ErrorMatches, `the authorization policy for the lockout hierarchy is invalid`)
	c.Check(err, Equals, ErrInvalidLockoutAuthPolicy)
}
