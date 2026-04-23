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
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/snapcore/secboot/internal/testutil"
	"github.com/snapcore/secboot/internal/tpm2test"
	. "github.com/snapcore/secboot/tpm2"
)

type lockoutauthSuiteMixin struct{}

func (*lockoutauthSuiteMixin) newDefaultLockoutAuthPolicy(c *C, alg tpm2.HashAlgorithmId) (tpm2.Digest, *policyutil.Policy) {
	digest, policy, err := NewDefaultLockoutAuthPolicy(alg)
	c.Assert(err, IsNil)
	return digest, policy
}

func (*lockoutauthSuiteMixin) newUpdateAuthValueLockoutAuthPolicy(c *C, alg tpm2.HashAlgorithmId, oldAuthValue []byte) (tpm2.Digest, *policyutil.Policy) {
	digest, policy, _, _, err := NewUpdateAuthValueLockoutAuthPolicy(alg, oldAuthValue)
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

func (s *lockoutauthSuiteNoTPM) newUpdateAuthValueLockoutAuthPolicy(c *C, alg tpm2.HashAlgorithmId, oldAuthValue []byte) *policyutil.Policy {
	_, policy := s.lockoutauthSuiteMixin.newUpdateAuthValueLockoutAuthPolicy(c, alg, oldAuthValue)
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
	c.Check(data, DeepEquals, []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw=="}`))
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
	oldAuthValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	params := &LockoutAuthParams{
		AuthValue:     oldAuthValue,
		AuthPolicy:    s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256),
		NewAuthValue:  testutil.DecodeHexString(c, "db82cbebd10ebd831b48ff8ae7275a23029074ba622c0416d97cd34dd38d8186"),
		NewAuthPolicy: s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, oldAuthValue),
	}

	data, err := json.Marshal(params)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw==","new-auth-value":"24LL69EOvYMbSP+K5ydaIwKQdLpiLAQW2XzTTdONgYY=","new-auth-policy":"AAAAAAAAAAEAC5DfGyoZIDr7uGD9ECZEKhrZck2HJ0rF/69uTv7L2r3uAAAAAAAAAAEgAQFxAAAAAgAAAAAAAQAL/g0OavvRqALD6F4sJD+kB1TWHYxCvdViNHPYjqSJqbIAAAACAAABbAAAAS4AAAFrAAAAAAABAAsKthPA+41TP+NED+noTBLANfaL5uN0SRiSp+yGd9FacwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIJPBCN9d627hW/UNWTj/zIeY9y/tgFeFqnhJxu3ru9obACAsVNPpCVnGvmNHgQA0M677rio72lnxr4kSG0z1nF1IVQARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA="}`))
}

func (s *lockoutauthSuiteNoTPM) TestLockoutAuthParamsUnmarshalJSON(c *C) {
	data := []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw=="}`)

	expected := &LockoutAuthParams{
		AuthValue:  testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1"),
		AuthPolicy: s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256),
	}

	var params *LockoutAuthParams
	c.Assert(json.Unmarshal(data, &params), IsNil)
	c.Check(params, DeepEquals, expected)
}

func (s *lockoutauthSuiteNoTPM) TestLockoutAuthParamsUnmarshalJSONForChangeAuth(c *C) {
	data := []byte(`{"auth-value":"x9oO1va6Pz6nQeeGOgoXSBOLbsyw4IQTKwSpyXbw0LE=","auth-policy":"AAAAAAAAAAEAC8fpxFXFnW/i+VVUXTr6s3kopn5+LbHkhqxSYqdusGu/AAAAAAAAAAIgAQFxAAAABQAAAAAAAQALtsXAXlgZCc3qffel+RwPLu03/XbxVSLu5bVfiW8tVj8AAAABAAABbAAAATkAAAAAAAEACxxoJ3ydZWTdgbzPfla6PtyrOI/GDOlbOkQr0nJY9g38AAAAAQAAAWwAAAE6AAAAAAABAAuUDPtCF7se3Pf7QZN8qXSqaOaYq3i4EksHARPiEf1G/AAAAAEAAAFsAAABJwAAAAAAAQALxN+rztqN6DbJVmGVKJKx3vcgOvtG/v7EP/z8k75UBzAAAAABAAABbAAAASYAAAAAAAEAC3G+h1vfkVM3lejs6YjXVDuULEStbQE7L3xfQ4MLi6IXAAAAAQAAAWwAAAEuAAABaw==","new-auth-value":"24LL69EOvYMbSP+K5ydaIwKQdLpiLAQW2XzTTdONgYY=","new-auth-policy":"AAAAAAAAAAEAC5DfGyoZIDr7uGD9ECZEKhrZck2HJ0rF/69uTv7L2r3uAAAAAAAAAAEgAQFxAAAAAgAAAAAAAQAL/g0OavvRqALD6F4sJD+kB1TWHYxCvdViNHPYjqSJqbIAAAACAAABbAAAAS4AAAFrAAAAAAABAAsKthPA+41TP+NED+noTBLANfaL5uN0SRiSp+yGd9FacwAAAAIAAAFsAAABKQAAAWAAIwALAAQAAAAAABAAEAADABAAIJPBCN9d627hW/UNWTj/zIeY9y/tgFeFqnhJxu3ru9obACAsVNPpCVnGvmNHgQA0M677rio72lnxr4kSG0z1nF1IVQARVVBEQVRFLUFVVEgtVkFMVUUAAAAAAAA="}`)

	oldAuthValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	expected := &LockoutAuthParams{
		AuthValue:     oldAuthValue,
		AuthPolicy:    s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256),
		NewAuthValue:  testutil.DecodeHexString(c, "db82cbebd10ebd831b48ff8ae7275a23029074ba622c0416d97cd34dd38d8186"),
		NewAuthPolicy: s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, oldAuthValue),
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

func (s *lockoutauthSuiteNoTPM) TestNewDefaultLockoutAuthPolicySHA256(c *C) {
	digest, policy, err := NewDefaultLockoutAuthPolicy(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(testutil.DecodeHexString(c, "c7e9c455c59d6fe2f955545d3afab37928a67e7e2db1e486ac5262a76eb06bbf")))
	c.Check(policy.String(), Equals, `
Policy {
 # digest TPM_ALG_SHA256:0xc7e9c455c59d6fe2f955545d3afab37928a67e7e2db1e486ac5262a76eb06bbf
 BranchNode {
   Branch 0 {
    # digest TPM_ALG_SHA256:0xb6c5c05e581909cdea7df7a5f91c0f2eed37fd76f15522eee5b55f896f2d563f
    PolicyCommandCode(TPM_CC_DictionaryAttackLockReset)
   }
   Branch 1 {
    # digest TPM_ALG_SHA256:0x1c68277c9d6564dd81bccf7e56ba3edcab388fc60ce95b3a442bd27258f60dfc
    PolicyCommandCode(TPM_CC_DictionaryAttackParameters)
   }
   Branch 2 {
    # digest TPM_ALG_SHA256:0x940cfb4217bb1edcf7fb41937ca974aa68e698ab78b8124b070113e211fd46fc
    PolicyCommandCode(TPM_CC_ClearControl)
   }
   Branch 3 {
    # digest TPM_ALG_SHA256:0xc4dfabceda8de836c95661952892b1def7203afb46fefec43ffcfc93be540730
    PolicyCommandCode(TPM_CC_Clear)
   }
   Branch 4 {
    # digest TPM_ALG_SHA256:0x71be875bdf91533795e8ece988d7543b942c44ad6d013b2f7c5f43830b8ba217
    PolicyCommandCode(TPM_CC_SetPrimaryPolicy)
   }
 }
 PolicyOR(
  0xb6c5c05e581909cdea7df7a5f91c0f2eed37fd76f15522eee5b55f896f2d563f
  0x1c68277c9d6564dd81bccf7e56ba3edcab388fc60ce95b3a442bd27258f60dfc
  0x940cfb4217bb1edcf7fb41937ca974aa68e698ab78b8124b070113e211fd46fc
  0xc4dfabceda8de836c95661952892b1def7203afb46fefec43ffcfc93be540730
  0x71be875bdf91533795e8ece988d7543b942c44ad6d013b2f7c5f43830b8ba217
 )
 PolicyAuthValue()
}`)
}

func (s *lockoutauthSuiteNoTPM) TestNewDefaultLockoutAuthPolicySHA384(c *C) {
	digest, policy, err := NewDefaultLockoutAuthPolicy(tpm2.HashAlgorithmSHA384)
	c.Assert(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(testutil.DecodeHexString(c, "7a99094f13bb180eeff7a54e0b86c394a8dd289e058d9d4583a98612959aefe67e2d0d6728c7645b3e6cc76da99dbce0")))
	c.Check(policy.String(), Equals, `
Policy {
 # digest TPM_ALG_SHA384:0x7a99094f13bb180eeff7a54e0b86c394a8dd289e058d9d4583a98612959aefe67e2d0d6728c7645b3e6cc76da99dbce0
 BranchNode {
   Branch 0 {
    # digest TPM_ALG_SHA384:0x3ba274a8092cf382fbf5cec7070e8f89043f3399fd9d5851693d0a87b0e40c35e6ac461c959ec090e35c071e2499cf90
    PolicyCommandCode(TPM_CC_DictionaryAttackLockReset)
   }
   Branch 1 {
    # digest TPM_ALG_SHA384:0x2f61a497478e81f1d3f58d641979241378d523dd2a5d8eb006d4f662092c8b71e0793750c03e56907e1044306c9d8002
    PolicyCommandCode(TPM_CC_DictionaryAttackParameters)
   }
   Branch 2 {
    # digest TPM_ALG_SHA384:0x2eb708fa8e860ef25c7e960c2b6814c4316eabe6d43613ee10231c7fa0467dca9c4e7abad35448c6be7a460a61ffca6f
    PolicyCommandCode(TPM_CC_ClearControl)
   }
   Branch 3 {
    # digest TPM_ALG_SHA384:0x55a038b340fb2776e89042f8e1a63f475d6ed129ce1a5da35c2d6c9225c12ba2e259242a771907bad2caa16e66e00bb0
    PolicyCommandCode(TPM_CC_Clear)
   }
   Branch 4 {
    # digest TPM_ALG_SHA384:0x95a762e430271f6b2ce625d7855536ae395b0cd99891219be02ed906a0fe783c4ac9012bb85488e96639fcb6f8a6964d
    PolicyCommandCode(TPM_CC_SetPrimaryPolicy)
   }
 }
 PolicyOR(
  0x3ba274a8092cf382fbf5cec7070e8f89043f3399fd9d5851693d0a87b0e40c35e6ac461c959ec090e35c071e2499cf90
  0x2f61a497478e81f1d3f58d641979241378d523dd2a5d8eb006d4f662092c8b71e0793750c03e56907e1044306c9d8002
  0x2eb708fa8e860ef25c7e960c2b6814c4316eabe6d43613ee10231c7fa0467dca9c4e7abad35448c6be7a460a61ffca6f
  0x55a038b340fb2776e89042f8e1a63f475d6ed129ce1a5da35c2d6c9225c12ba2e259242a771907bad2caa16e66e00bb0
  0x95a762e430271f6b2ce625d7855536ae395b0cd99891219be02ed906a0fe783c4ac9012bb85488e96639fcb6f8a6964d
 )
 PolicyAuthValue()
}`)
}

func (s *lockoutauthSuiteNoTPM) TestNewUpdateLockoutAuthValueKey1(c *C) {
	expectedKey := testutil.ParsePKCS8PrivateKey(c, testutil.DecodePEMType(c, "PRIVATE KEY", []byte(
		`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1oJePIX4hsogCSC7
j4ksaKoo2TcbpsOzFi8Lw/rGm/yhRANCAATbaksKtS3jGTcjak+iFxEQVIPuXWKS
D/DzsdvswsWgTu81WK33zdFS52uyeOmUjLYpcxLWVHGop7+jR3vTlFMj
-----END PRIVATE KEY-----
`)))
	c.Assert(expectedKey, testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	expectedPubKey := &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
			},
		},
		Unique: &tpm2.PublicIDU{
			ECC: &tpm2.ECCPoint{
				X: expectedKey.(*ecdsa.PrivateKey).X.Bytes(),
				Y: expectedKey.(*ecdsa.PrivateKey).Y.Bytes(),
			},
		},
	}

	key, pubKey, err := NewUpdateLockoutAuthValueKey(testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427cea"))
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, expectedKey)
	c.Check(pubKey, DeepEquals, expectedPubKey)
}

func (s *lockoutauthSuiteNoTPM) TestNewUpdateLockoutAuthValueKey2(c *C) {
	expectedKey := testutil.ParsePKCS8PrivateKey(c, testutil.DecodePEMType(c, "PRIVATE KEY", []byte(
		`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWJgFCvqXoNkxelii
gSQkkQFhoB4c6wspl+bG3WZagKWhRANCAARcyMkoEYURupGLO7gkXO8VDkJUhxoh
ckDarAbDcRnWc+Smt2x6Jct+Ft/81OlYZKZTkIQlM4CMWnr3a5zGPp1Z
-----END PRIVATE KEY-----
`)))
	c.Assert(expectedKey, testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	expectedPubKey := &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
			},
		},
		Unique: &tpm2.PublicIDU{
			ECC: &tpm2.ECCPoint{
				X: expectedKey.(*ecdsa.PrivateKey).X.Bytes(),
				Y: expectedKey.(*ecdsa.PrivateKey).Y.Bytes(),
			},
		},
	}
	key, pubKey, err := NewUpdateLockoutAuthValueKey(testutil.DecodeHexString(c, "f10fa81ad01d6912916951039ed6a06c33f6995a5b6cd307f246d2dd6551edce"))
	c.Assert(err, IsNil)
	c.Check(key, DeepEquals, expectedKey)
	c.Check(pubKey, DeepEquals, expectedPubKey)
}

func (s *lockoutauthSuiteNoTPM) TestNewUpdateAuthValueLockoutAuthPolicySHA256_1(c *C) {
	expectedKey := testutil.ParsePKCS8PrivateKey(c, testutil.DecodePEMType(c, "PRIVATE KEY", []byte(
		`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1oJePIX4hsogCSC7
j4ksaKoo2TcbpsOzFi8Lw/rGm/yhRANCAATbaksKtS3jGTcjak+iFxEQVIPuXWKS
D/DzsdvswsWgTu81WK33zdFS52uyeOmUjLYpcxLWVHGop7+jR3vTlFMj
-----END PRIVATE KEY-----
`)))
	c.Assert(expectedKey, testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	expectedPubKey := &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
			},
		},
		Unique: &tpm2.PublicIDU{
			ECC: &tpm2.ECCPoint{
				X: expectedKey.(*ecdsa.PrivateKey).X.Bytes(),
				Y: expectedKey.(*ecdsa.PrivateKey).Y.Bytes(),
			},
		},
	}

	digest, policy, key, pubKey, err := NewUpdateAuthValueLockoutAuthPolicy(tpm2.HashAlgorithmSHA256, testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427cea"))
	c.Assert(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(testutil.DecodeHexString(c, "414b075b442067d58879f8bce5fcc76d2eff43d6fba5c5f1fe7fd56509f2abea")))
	c.Check(policy.String(), Equals, `
Policy {
 # digest TPM_ALG_SHA256:0x414b075b442067d58879f8bce5fcc76d2eff43d6fba5c5f1fe7fd56509f2abea
 BranchNode {
   Branch 0 {
    # digest TPM_ALG_SHA256:0xfe0d0e6afbd1a802c3e85e2c243fa40754d61d8c42bdd5623473d88ea489a9b2
    PolicyCommandCode(TPM_CC_SetPrimaryPolicy)
    PolicyAuthValue()
   }
   Branch 1 {
    # digest TPM_ALG_SHA256:0xb1b14d96221d908f547563b6895afc7e2d0127e5dae57b3d4a77492199ceddbb
    PolicyCommandCode(TPM_CC_HierarchyChangeAuth)
    PolicySigned(authKey:0x000b4ec2a02411b7ee0f601465fe178d7dc02b3b9b8821b873a4486f9edc48bdcc41, policyRef:0x5550444154452d415554482d56414c5545)
   }
 }
 PolicyOR(
  0xfe0d0e6afbd1a802c3e85e2c243fa40754d61d8c42bdd5623473d88ea489a9b2
  0xb1b14d96221d908f547563b6895afc7e2d0127e5dae57b3d4a77492199ceddbb
 )
}`)
	c.Check(key, DeepEquals, expectedKey)
	c.Check(pubKey, DeepEquals, expectedPubKey)
}

func (s *lockoutauthSuiteNoTPM) TestNewUpdateAuthValueLockoutAuthPolicySHA256_2(c *C) {
	expectedKey := testutil.ParsePKCS8PrivateKey(c, testutil.DecodePEMType(c, "PRIVATE KEY", []byte(
		`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWJgFCvqXoNkxelii
gSQkkQFhoB4c6wspl+bG3WZagKWhRANCAARcyMkoEYURupGLO7gkXO8VDkJUhxoh
ckDarAbDcRnWc+Smt2x6Jct+Ft/81OlYZKZTkIQlM4CMWnr3a5zGPp1Z
-----END PRIVATE KEY-----
`)))
	c.Assert(expectedKey, testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	expectedPubKey := &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
			},
		},
		Unique: &tpm2.PublicIDU{
			ECC: &tpm2.ECCPoint{
				X: expectedKey.(*ecdsa.PrivateKey).X.Bytes(),
				Y: expectedKey.(*ecdsa.PrivateKey).Y.Bytes(),
			},
		},
	}

	digest, policy, key, pubKey, err := NewUpdateAuthValueLockoutAuthPolicy(tpm2.HashAlgorithmSHA256, testutil.DecodeHexString(c, "f10fa81ad01d6912916951039ed6a06c33f6995a5b6cd307f246d2dd6551edce"))
	c.Assert(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(testutil.DecodeHexString(c, "f337a695eaa950db2c3a7cc0d81a32b0b3bc371ca41f2f6a674e9b30cc2a640f")))
	c.Check(policy.String(), Equals, `
Policy {
 # digest TPM_ALG_SHA256:0xf337a695eaa950db2c3a7cc0d81a32b0b3bc371ca41f2f6a674e9b30cc2a640f
 BranchNode {
   Branch 0 {
    # digest TPM_ALG_SHA256:0xfe0d0e6afbd1a802c3e85e2c243fa40754d61d8c42bdd5623473d88ea489a9b2
    PolicyCommandCode(TPM_CC_SetPrimaryPolicy)
    PolicyAuthValue()
   }
   Branch 1 {
    # digest TPM_ALG_SHA256:0x4ab1bdea476a5b2225559debabede03de1cf73e48a5b074100ed1f7abceeb3e5
    PolicyCommandCode(TPM_CC_HierarchyChangeAuth)
    PolicySigned(authKey:0x000bfaf0669b1825822c25d65ac160d9a196071cd4dcab0771ea2c2a26f7857cdc85, policyRef:0x5550444154452d415554482d56414c5545)
   }
 }
 PolicyOR(
  0xfe0d0e6afbd1a802c3e85e2c243fa40754d61d8c42bdd5623473d88ea489a9b2
  0x4ab1bdea476a5b2225559debabede03de1cf73e48a5b074100ed1f7abceeb3e5
 )
}`)
	c.Check(key, DeepEquals, expectedKey)
	c.Check(pubKey, DeepEquals, expectedPubKey)
}

func (s *lockoutauthSuiteNoTPM) TestNewUpdateAuthValueLockoutAuthPolicySHA384(c *C) {
	expectedKey := testutil.ParsePKCS8PrivateKey(c, testutil.DecodePEMType(c, "PRIVATE KEY", []byte(
		`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAmD9n1YetaEB1uJN
NT1s5GMSSfWcYwso8RgVg+AU+4ihRANCAATy+Fer194BjW3IyIBFYg3wrpgPiTjn
GpiUnHWuinAp5fLWFgVmEbcaNRSzyqGRkq+NtgDCeDNsXUwmBj0/XVKR
-----END PRIVATE KEY-----
`)))
	c.Assert(expectedKey, testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	expectedPubKey := &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
			},
		},
		Unique: &tpm2.PublicIDU{
			ECC: &tpm2.ECCPoint{
				X: expectedKey.(*ecdsa.PrivateKey).X.Bytes(),
				Y: expectedKey.(*ecdsa.PrivateKey).Y.Bytes(),
			},
		},
	}

	digest, policy, key, pubKey, err := NewUpdateAuthValueLockoutAuthPolicy(tpm2.HashAlgorithmSHA384, testutil.DecodeHexString(c, "c04c673608034f3f6fdd1b2ba752daf8ae5fa9ca5d7fc21b5f5f1dbdd9427ceaa6f35c0d0f98c2926a0b029296f06cc5"))
	c.Assert(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(testutil.DecodeHexString(c, "a879336fa8f97b75ec5c599c442e40cbb5780af95cd9540627d0d013be68a6a7b57fd878f5a88a41dae7972ccb49b47a")))
	c.Check(policy.String(), Equals, `
Policy {
 # digest TPM_ALG_SHA384:0xa879336fa8f97b75ec5c599c442e40cbb5780af95cd9540627d0d013be68a6a7b57fd878f5a88a41dae7972ccb49b47a
 BranchNode {
   Branch 0 {
    # digest TPM_ALG_SHA384:0xf0a1e926f1405be83accb5e93fa8d6df69a72c61df0082013224da28d78902bbb58e7c5bfdadf05cac8cfd115043aae8
    PolicyCommandCode(TPM_CC_SetPrimaryPolicy)
    PolicyAuthValue()
   }
   Branch 1 {
    # digest TPM_ALG_SHA384:0x17b334cb9352973354c6a7b9065d9b49ed2013522d1e056d6f9d2b1650d0b067b4064799632c4acd5085aa66c97a6396
    PolicyCommandCode(TPM_CC_HierarchyChangeAuth)
    PolicySigned(authKey:0x000bd49793418a9917c56ed403a8791f8254d153b1ca1b6ea698595d4bb76f513556, policyRef:0x5550444154452d415554482d56414c5545)
   }
 }
 PolicyOR(
  0xf0a1e926f1405be83accb5e93fa8d6df69a72c61df0082013224da28d78902bbb58e7c5bfdadf05cac8cfd115043aae8
  0x17b334cb9352973354c6a7b9065d9b49ed2013522d1e056d6f9d2b1650d0b067b4064799632c4acd5085aa66c97a6396
 )
}`)
	c.Check(key, DeepEquals, expectedKey)
	c.Check(pubKey, DeepEquals, expectedPubKey)
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
	if resetErr != nil && !errors.Is(resetErr, ErrLockoutAuthNotInitialized) {
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
	c.Check(err, ErrorMatches, `the authorization parameters for the lockout hierarchy are not fully initialized`)
	c.Check(err, Equals, ErrLockoutAuthNotInitialized)

	cmds := s.CommandLog()
	c.Assert(len(cmds) > 2, testutil.IsTrue)
	cmd := cmds[len(cmds)-3]
	c.Check(cmd.CmdCode, Equals, tpm2.CommandDictionaryAttackLockReset)
	c.Assert(cmd.CmdAuthArea, HasLen, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle.Type(), Equals, tpm2.HandleTypePolicySession)

	c.Check(s.TPM().DoesHandleExist(cmd.CmdAuthArea[0].SessionHandle), testutil.IsFalse)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockAuthPolicyUnset(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	_, policy := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		policyAlg: tpm2.HashAlgorithmNull,
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthValue:  authValue,
			AuthPolicy: policy,
		}),
	})
	c.Check(err, ErrorMatches, `the authorization parameters for the lockout hierarchy are not fully initialized`)
	c.Check(err, Equals, ErrLockoutAuthNotInitialized)

	cmds := s.CommandLog()
	c.Assert(len(cmds) > 1, testutil.IsTrue)
	cmd := cmds[len(cmds)-2]
	c.Check(cmd.CmdCode, Equals, tpm2.CommandDictionaryAttackLockReset)
	c.Assert(cmd.CmdAuthArea, HasLen, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle.Type(), Equals, tpm2.HandleTypeHMACSession)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockNoAuthPolicySupport(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		authValue: authValue,
		policyAlg: tpm2.HashAlgorithmNull,
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthValue: authValue,
		}),
	})
	c.Check(err, IsNil)

	cmds := s.CommandLog()
	c.Assert(len(cmds) > 1, testutil.IsTrue)
	cmd := cmds[len(cmds)-2]
	c.Check(cmd.CmdCode, Equals, tpm2.CommandDictionaryAttackLockReset)
	c.Assert(cmd.CmdAuthArea, HasLen, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle.Type(), Equals, tpm2.HandleTypeHMACSession)
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

func (s *lockoutauthSuite) TestResetDictionaryAttackLockInterruptedAuthValueRotation1(c *C) {
	authValue := testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1")
	digest, policy := s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, authValue)

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
	c.Check(err, ErrorMatches, `the authorization parameters for the lockout hierarchy are invalid`)
	c.Check(err, Equals, ErrLockoutAuthInvalid)
}

func (s *lockoutauthSuite) TestResetDictionaryAttackLockInterruptedAuthValueRotation2(c *C) {
	authValue := testutil.DecodeHexString(c, "db82cbebd10ebd831b48ff8ae7275a23029074ba622c0416d97cd34dd38d8186")
	digest, policy1 := s.newUpdateAuthValueLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256, testutil.DecodeHexString(c, "c7da0ed6f6ba3f3ea741e7863a0a1748138b6eccb0e084132b04a9c976f0d0b1"))
	_, policy2 := s.newDefaultLockoutAuthPolicy(c, tpm2.HashAlgorithmSHA256)

	err := s.testResetDictionaryAttackLock(c, &testResetDictionaryAttackLockParams{
		authValue:    authValue,
		policyDigest: digest,
		policyAlg:    tpm2.HashAlgorithmSHA256,
		data: s.makeLockoutAuthData(c, &LockoutAuthParams{
			AuthValue:     authValue,
			AuthPolicy:    policy1,
			NewAuthPolicy: policy2,
		}),
	})
	c.Check(err, ErrorMatches, `the authorization parameters for the lockout hierarchy are invalid`)
	c.Check(err, Equals, ErrLockoutAuthInvalid)
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
	c.Check(err, ErrorMatches, `the authorization parameters for the lockout hierarchy are invalid`)
	c.Check(err, Equals, ErrLockoutAuthInvalid)
}
