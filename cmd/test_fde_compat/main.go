package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bsiegert/ranges"
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/jessevdk/go-flags"
	secboot_efi "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/snapd/snap/snapdir"
	"github.com/snapcore/snapd/snap/squashfs"
)

type pcrRange []tpm2.Handle

func (r pcrRange) MarshalFlag() (string, error) {
	var s []string
	for _, p := range r {
		s = append(s, strconv.FormatUint(uint64(p), 10))
	}
	return strings.Join(s, ","), nil
}

func (r *pcrRange) UnmarshalFlag(value string) error {
	i, err := ranges.Parse(value)
	if err != nil {
		return err
	}
	for _, p := range i {
		*r = append(*r, tpm2.Handle(p))
	}
	return nil
}

func (r *pcrRange) Contains(index tpm2.Handle) bool {
	for _, p := range *r {
		if p == index {
			return true
		}
	}
	return false
}

type options struct {
	Check struct {
		PostInstall               bool     `long:"post-install" description:"Run the checks post-install rather than pre-install"`
		PermitVM                  bool     `long:"permit-vm" description:"Permit running inside of a virtual machine"`
		PermitVARSuppliedDrivers  bool     `long:"permit-var-supplied-drivers" description:"Permit drivers from value-added-retailer supplied components to be running"`
		PermitSysPrepApplications bool     `long:"permit-sysprep-apps" description:"Permit system preparation applications to be running"`
		PermitAbsoluteComputrace  bool     `long:"permit-absolute" description:"Permit the Absolute firmware component to be running and measured to PCR4"`
		MandatoryPCRs             pcrRange `long:"mandatory-pcrs" description:"Which PCRs should support be mandatory"`
	} `group:"Check options"`

	Profile struct {
		MostSecure                     bool `long:"most-secure" description:"Select the most secure PCR profile"`
		TrustCAsForBootCode            bool `long:"trust-authorities-for-boot-code" description:"Trust the secure boot CAs used to authenticate code on this system to authenticate any boot code (definitely not advisable for the Microsoft UEFI CA)"`
		TrustCAsForVARSuppliedDrivers  bool `long:"trust-authorities-for-var-supplied-drivers" description:"Trust the secure boot CAs used to authenticate code on this system to authenticate any value-added-retailer supplied firmware driver (most likely not advisable for the Microsoft UEFI CA)"`
		DistrustVARSuppliedNonHostCode bool `long:"distrust-var-supplied-nonhost-code" description:"Distrust code running in value-added-retailer supplied embedded controllers. This code doesn't run on the CPU and isn't part of the trust chain, but can potentially still affect trust"`
		NoDiscreteTPMResetMitigation   bool `long:"no-discrete-tpm-reset-mitigation" description:"Disable mitigations against discrete TPM reset attacks where appropriate"`
	} `group:"PCR profile options"`

	Positional struct {
		BootImages []string `positional-arg-name:"ordered paths to the EFI boot components for the current boot"`
	} `positional-args:"true"`
}

var opts options

func run() error {
	if _, err := flags.Parse(&opts); err != nil {
		return err
	}

	var checkFlags preinstall.CheckFlags
	if opts.Check.PostInstall {
		checkFlags |= preinstall.PostInstallChecks
	}
	if opts.Check.PermitVM {
		checkFlags |= preinstall.PermitVirtualMachine
	}
	if opts.Check.PermitVARSuppliedDrivers {
		checkFlags |= preinstall.PermitVARSuppliedDrivers
	}
	if opts.Check.PermitSysPrepApplications {
		checkFlags |= preinstall.PermitSysPrepApplications
	}
	if opts.Check.PermitAbsoluteComputrace {
		checkFlags |= preinstall.PermitAbsoluteComputrace
	}
	if opts.Check.MandatoryPCRs.Contains(0) {
		checkFlags |= preinstall.PlatformFirmwareProfileSupportRequired
	}
	if opts.Check.MandatoryPCRs.Contains(1) {
		checkFlags |= preinstall.PlatformConfigProfileSupportRequired
	}
	if opts.Check.MandatoryPCRs.Contains(2) {
		checkFlags |= preinstall.DriversAndAppsProfileSupportRequired
	}
	if opts.Check.MandatoryPCRs.Contains(3) {
		checkFlags |= preinstall.DriversAndAppsConfigProfileSupportRequired
	}
	if opts.Check.MandatoryPCRs.Contains(4) {
		checkFlags |= preinstall.BootManagerCodeProfileSupportRequired
	}
	if opts.Check.MandatoryPCRs.Contains(5) {
		checkFlags |= preinstall.BootManagerConfigProfileSupportRequired
	}
	if opts.Check.MandatoryPCRs.Contains(7) {
		checkFlags |= preinstall.SecureBootPolicyProfileSupportRequired
	}

	var bootImages []secboot_efi.Image
	for _, img := range opts.Positional.BootImages {
		var snapPath string
		var filePath string
		if n, err := fmt.Sscanf("squashfs:%s(%s)", img, &snapPath, &filePath); err == nil && n == 2 {
			container := squashfs.New(snapPath)
			bootImages = append(bootImages, secboot_efi.NewSnapFileImage(container, filePath))
		} else if n, err := fmt.Sscanf("snapdir:%s(%s)", img, &snapPath, filePath); err == nil && n == 2 {
			container := snapdir.New(snapPath)
			bootImages = append(bootImages, secboot_efi.NewSnapFileImage(container, filePath))
		} else {
			bootImages = append(bootImages, secboot_efi.NewFileImage(img))
		}
	}

	fmt.Println("Testing for compatibility with EFI based TPM protected FDE")

	result, err := preinstall.RunChecks(efi.DefaultVarContext, checkFlags, bootImages)
	if err != nil {
		return err
	}

	fmt.Printf("%v\n", result)

	var pcrFlags preinstall.PCRProfileOptionsFlags
	if opts.Profile.MostSecure {
		pcrFlags |= preinstall.PCRProfileOptionMostSecure
	}
	if opts.Profile.TrustCAsForBootCode {
		pcrFlags |= preinstall.PCRProfileOptionTrustCAsForBootCode
	}
	if opts.Profile.TrustCAsForVARSuppliedDrivers {
		pcrFlags |= preinstall.PCRProfileOptionTrustCAsForVARSuppliedDrivers
	}
	if opts.Profile.DistrustVARSuppliedNonHostCode {
		pcrFlags |= preinstall.PCRProfileOptionDistrustVARSuppliedNonHostCode
	}
	if opts.Profile.NoDiscreteTPMResetMitigation {
		pcrFlags |= preinstall.PCRProfileOptionNoDiscreteTPMResetMitigation
	}

	profile := preinstall.WithAutoPCRProfile(result, pcrFlags)
	pcrs, err := profile.PCRs()
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Selected TCG PCRs:", pcrs)

	return nil
}

func main() {
	if err := run(); err != nil {
		switch e := err.(type) {
		case *flags.Error:
			// flags already prints this
			if e.Type != flags.ErrHelp {
				os.Exit(1)
			}
		default:
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "This platform is not suitable for FDE:\n", err)
		}
	}
}
