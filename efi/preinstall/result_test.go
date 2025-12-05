/*
 * Copyright (C) 2024 Canonical Ltd
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

package preinstall_test

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	. "github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/secboot/internal/testutil"
	. "gopkg.in/check.v1"
)

type resultSuite struct{}

var _ = Suite(&resultSuite{})

func (s *resultSuite) TestCheckResultFlagsMarshalJSON(c *C) {
	for _, params := range []struct {
		flags    CheckResultFlags
		expected string
	}{
		{flags: NoPlatformFirmwareProfileSupport, expected: `["no-platform-firmware-profile-support"]`},
		{flags: NoPlatformConfigProfileSupport, expected: `["no-platform-config-profile-support"]`},
		{flags: NoDriversAndAppsProfileSupport, expected: `["no-drivers-and-apps-profile-support"]`},
		{flags: NoDriversAndAppsConfigProfileSupport, expected: `["no-drivers-and-apps-config-profile-support"]`},
		{flags: NoBootManagerCodeProfileSupport, expected: `["no-boot-manager-code-profile-support"]`},
		{flags: NoBootManagerConfigProfileSupport, expected: `["no-boot-manager-config-profile-support"]`},
		{flags: NoSecureBootPolicyProfileSupport, expected: `["no-secure-boot-policy-profile-support"]`},
		{flags: RequestPartialDiscreteTPMResetAttackMitigation, expected: `["request-partial-dtpm-reset-attack-mitigation"]`},
		{flags: InsufficientDMAProtectionDetected, expected: `["insufficient-dma-protection-detected"]`},
		{flags: NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport, expected: `["no-platform-config-profile-support","no-drivers-and-apps-config-profile-support","no-boot-manager-config-profile-support"]`},
	} {
		data, err := json.Marshal(params.flags)
		c.Check(err, IsNil, Commentf("flags:%v", params.flags))
		c.Check(data, DeepEquals, []byte(params.expected), Commentf("flags:%v", params.flags))
	}
}

func (s *resultSuite) TestCheckResultFlagsUnmarshalJSON(c *C) {
	for _, params := range []struct {
		flags    string
		expected CheckResultFlags
	}{
		{flags: `["no-platform-firmware-profile-support"]`, expected: NoPlatformFirmwareProfileSupport},
		{flags: `["no-platform-config-profile-support"]`, expected: NoPlatformConfigProfileSupport},
		{flags: `["no-drivers-and-apps-profile-support"]`, expected: NoDriversAndAppsProfileSupport},
		{flags: `["no-drivers-and-apps-config-profile-support"]`, expected: NoDriversAndAppsConfigProfileSupport},
		{flags: `["no-boot-manager-code-profile-support"]`, expected: NoBootManagerCodeProfileSupport},
		{flags: `["no-boot-manager-config-profile-support"]`, expected: NoBootManagerConfigProfileSupport},
		{flags: `["no-secure-boot-policy-profile-support"]`, expected: NoSecureBootPolicyProfileSupport},
		{flags: `["request-partial-dtpm-reset-attack-mitigation"]`, expected: RequestPartialDiscreteTPMResetAttackMitigation},
		{flags: `["insufficient-dma-protection-detected"]`, expected: InsufficientDMAProtectionDetected},
		{flags: `["no-platform-config-profile-support","no-drivers-and-apps-config-profile-support","no-boot-manager-config-profile-support"]`, expected: NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport},
		{flags: `["0x8"]`, expected: NoDriversAndAppsConfigProfileSupport},
		{flags: `["32"]`, expected: NoBootManagerConfigProfileSupport},
		{flags: `["discrete-tpm-detected"]`, expected: RequestPartialDiscreteTPMResetAttackMitigation},
		{flags: `["discrete-tpm-detected","startup-locality-not-protected"]`, expected: 0},
	} {
		var flags CheckResultFlags
		c.Check(json.Unmarshal([]byte(params.flags), &flags), IsNil, Commentf("flags:%q", params.flags))
		c.Check(flags, Equals, params.expected, Commentf("flags:%q", params.flags))
	}
}

func (s *resultSuite) TestCheckResultFlagsUnmarshalJSONInvalidSlice(c *C) {
	var flags CheckResultFlags
	c.Check(json.Unmarshal([]byte("foo"), &flags), ErrorMatches, `invalid character 'o' in literal false \(expecting 'a'\)`)
}

func (s *resultSuite) TestCheckResultFlagsUnmarshalJSONInvalidFlag(c *C) {
	var flags CheckResultFlags
	c.Check(json.Unmarshal([]byte(`["foo"]`), &flags), ErrorMatches, `unrecognized flag "foo"`)
}
func (s *resultSuite) TestCheckResultFlagsString(c *C) {
	for _, params := range []struct {
		flags    CheckResultFlags
		expected string
	}{
		{flags: NoPlatformFirmwareProfileSupport, expected: "no-platform-firmware-profile-support"},
		{flags: NoPlatformConfigProfileSupport, expected: "no-platform-config-profile-support"},
		{flags: NoDriversAndAppsProfileSupport, expected: "no-drivers-and-apps-profile-support"},
		{flags: NoDriversAndAppsConfigProfileSupport, expected: "no-drivers-and-apps-config-profile-support"},
		{flags: NoBootManagerCodeProfileSupport, expected: "no-boot-manager-code-profile-support"},
		{flags: NoBootManagerConfigProfileSupport, expected: "no-boot-manager-config-profile-support"},
		{flags: NoSecureBootPolicyProfileSupport, expected: "no-secure-boot-policy-profile-support"},
		{flags: RequestPartialDiscreteTPMResetAttackMitigation, expected: "request-partial-dtpm-reset-attack-mitigation"},
		{flags: InsufficientDMAProtectionDetected, expected: "insufficient-dma-protection-detected"},
		{flags: NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport, expected: "no-platform-config-profile-support,no-drivers-and-apps-config-profile-support,no-boot-manager-config-profile-support"},
	} {
		c.Check(params.flags.String(), Equals, params.expected, Commentf("flags:%#08x", params.flags))
	}
}

func (s *resultSuite) TestCheckResultMarshalJSON(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}"))
}

func (s *resultSuite) TestCheckResultMarshalJSONSHA384(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA384,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha384\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}"))
}

func (s *resultSuite) TestCheckResultMarshalJSONDifferentCA(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"ME4xCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xHzAdBgNVBAMTFk1pY3Jvc29mdCBVRUZJIENBIDIwMjM=\",\"subject-key-id\":\"gaprMkTJNbzg1mKK85gnQh4ySX0=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBSU0EgRGV2aWNlcyBSb290IENBIDIwMjE=\",\"authority-key-id\":\"hESGBgCYPyyqs8WJ86wuyeadCQM=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}"))
}

func (s *resultSuite) TestCheckResultMarshalJSONMultipleCAs(c *C) {
	result := CheckResult{
		PCRAlg: tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{
			NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert)),
			NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023)),
		},
		Flags: NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"},{\"subject\":\"ME4xCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xHzAdBgNVBAMTFk1pY3Jvc29mdCBVRUZJIENBIDIwMjM=\",\"subject-key-id\":\"gaprMkTJNbzg1mKK85gnQh4ySX0=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBSU0EgRGV2aWNlcyBSb290IENBIDIwMjE=\",\"authority-key-id\":\"hESGBgCYPyyqs8WJ86wuyeadCQM=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}"))
}

func (s *resultSuite) TestCheckResultMarshalJSONNoPlatformFirmareProfileSupport(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-firmware-profile-support\",\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}"))
}

func (s *resultSuite) TestCheckResultMarshalJSONNoDriversAndAppsProfileSupport(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}"))
}

func (s *resultSuite) TestCheckResultMarshalJSONNoBootManagerCodeProfileSupport(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-code-profile-support\",\"no-boot-manager-config-profile-support\"]}"))
}

func (s *resultSuite) TestCheckResultMarshalJSONNoSecureBootPolicyProfileSupport(c *C) {
	result := CheckResult{
		PCRAlg: tpm2.HashAlgorithmSHA256,
		Flags:  NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":null,\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\",\"no-secure-boot-policy-profile-support\"]}"))
}

func (s *resultSuite) TestCheckResultMarshalJSONRequestDTPMResetAttackMitigation(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | RequestPartialDiscreteTPMResetAttackMitigation,
	}
	data, err := json.Marshal(result)
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\",\"request-partial-dtpm-reset-attack-mitigation\"]}"))
}

func (s *resultSuite) TestCheckResultUnmarshalJSON(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONSHA384(c *C) {
	data := []byte("{\"pcr-alg\":\"sha384\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA384,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONDifferentCA(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"ME4xCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xHzAdBgNVBAMTFk1pY3Jvc29mdCBVRUZJIENBIDIwMjM=\",\"subject-key-id\":\"gaprMkTJNbzg1mKK85gnQh4ySX0=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBSU0EgRGV2aWNlcyBSb290IENBIDIwMjE=\",\"authority-key-id\":\"hESGBgCYPyyqs8WJ86wuyeadCQM=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONMultipleCAs(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"},{\"subject\":\"ME4xCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xHzAdBgNVBAMTFk1pY3Jvc29mdCBVRUZJIENBIDIwMjM=\",\"subject-key-id\":\"gaprMkTJNbzg1mKK85gnQh4ySX0=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBSU0EgRGV2aWNlcyBSb290IENBIDIwMjE=\",\"authority-key-id\":\"hESGBgCYPyyqs8WJ86wuyeadCQM=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg: tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{
			NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert)),
			NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert2023)),
		},
		Flags: NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONNoPlatformFirmareProfileSupport(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-firmware-profile-support\",\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformFirmwareProfileSupport | NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONNoDriversAndAppsProfileSupport(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONNoBootManagerCodeProfileSupport(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-code-profile-support\",\"no-boot-manager-config-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerCodeProfileSupport | NoBootManagerConfigProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONNoSecureBootPolicyProfileSupport(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":null,\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\",\"no-secure-boot-policy-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg: tpm2.HashAlgorithmSHA256,
		Flags:  NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | NoSecureBootPolicyProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONRequestDTPMResetAttackMitigation(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\",\"request-partial-dtpm-reset-attack-mitigation\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | RequestPartialDiscreteTPMResetAttackMitigation,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONDiscreteTPMDetected(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\",\"discrete-tpm-detected\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport | RequestPartialDiscreteTPMResetAttackMitigation,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONDiscreteTPMDetectedWithNoDTPMResetAttackMitigation(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\",\"discrete-tpm-detected\",\"startup-locality-not-protected\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), IsNil)
	c.Check(result, DeepEquals, &CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	})
}

func (s *resultSuite) TestCheckResultUnmarshalJSONUnrecognizedPCRAlg(c *C) {
	data := []byte("{\"pcr-alg\":\"sha3-256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), ErrorMatches, `cannot decode CheckResult: unrecognized PCR algorithm`)
}

func (s *resultSuite) TestCheckResultUnmarshalJSONCorruptSecureBootCA(c *C) {
	corruptCA, err := json.Marshal(NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert)))
	c.Assert(err, IsNil)
	corruptCA[10] = ';'
	data := []byte(fmt.Sprintf("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[%s],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\"]}", corruptCA))

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), ErrorMatches, `invalid character ';' after object key`)
}

func (s *resultSuite) TestCheckResultUnmarshalJSONUnrecognizedFlags(c *C) {
	data := []byte("{\"pcr-alg\":\"sha256\",\"used-secure-boot-cas\":[{\"subject\":\"MIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVUVGSSBDQSAyMDEx\",\"subject-key-id\":\"E62/Qwm9gnCcjNVPMW7VIpiKG9Q=\",\"pubkey-algorithm\":\"RSA\",\"issuer\":\"MIGRMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTswOQYDVQQDEzJNaWNyb3NvZnQgQ29ycG9yYXRpb24gVGhpcmQgUGFydHkgTWFya2V0cGxhY2UgUm9vdA==\",\"authority-key-id\":\"RWZSQ+F+WBG/1k6eI1UIOzoiaqg=\",\"signature-algorithm\":\"SHA256-RSA\"}],\"flags\":[\"no-platform-config-profile-support\",\"no-drivers-and-apps-config-profile-support\",\"no-boot-manager-config-profile-support\",\"var-drivers-present\"]}")

	var result *CheckResult
	c.Assert(json.Unmarshal(data, &result), ErrorMatches, `unrecognized flag \"var-drivers-present\"`)
}

func (s *resultSuite) TestCheckResultString(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
	}
	c.Check(result.String(), Equals, `
EFI based TPM protected FDE test support results:
- Best PCR algorithm: TPM_ALG_SHA256
- Secure boot CAs used for verification:
  1: subject=CN=Microsoft Corporation UEFI CA 2011,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US, SKID=0x13adbf4309bd82709c8cd54f316ed522988a1bd4, pubkeyAlg=RSA, issuer=CN=Microsoft Corporation Third Party Marketplace Root,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US, AKID=0x45665243e17e5811bfd64e9e2355083b3a226aa8, sigAlg=SHA256-RSA
- Flags: no-platform-config-profile-support,no-drivers-and-apps-config-profile-support,no-boot-manager-config-profile-support
`)
}

func (s *resultSuite) TestCheckResultStringWithWarnings(c *C) {
	result := CheckResult{
		PCRAlg:            tpm2.HashAlgorithmSHA256,
		UsedSecureBootCAs: []*X509CertificateID{NewX509CertificateID(testutil.ParseCertificate(c, msUefiCACert))},
		Flags:             NoPlatformConfigProfileSupport | NoDriversAndAppsConfigProfileSupport | NoBootManagerConfigProfileSupport,
		Warnings: JoinErrors(
			errors.New("some error 1"),
			errors.New(`some error 2
across more than one line`),
		).(CompoundError),
	}
	c.Check(result.String(), Equals, `
EFI based TPM protected FDE test support results:
- Best PCR algorithm: TPM_ALG_SHA256
- Secure boot CAs used for verification:
  1: subject=CN=Microsoft Corporation UEFI CA 2011,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US, SKID=0x13adbf4309bd82709c8cd54f316ed522988a1bd4, pubkeyAlg=RSA, issuer=CN=Microsoft Corporation Third Party Marketplace Root,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US, AKID=0x45665243e17e5811bfd64e9e2355083b3a226aa8, sigAlg=SHA256-RSA
- Flags: no-platform-config-profile-support,no-drivers-and-apps-config-profile-support,no-boot-manager-config-profile-support
- Warnings:
  - some error 1
  - some error 2
    across more than one line
`)
}
