package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"
	secboot_efi "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/efi/preinstall"
	"github.com/snapcore/snapd/snap/snapdir"
	"github.com/snapcore/snapd/snap/squashfs"
)

type options struct {
	Check struct {
		PostInstall                         bool `long:"post-install" description:"Run the checks post-install rather than pre-install"`
		PermitVM                            bool `long:"permit-vm" description:"Permit running inside of a virtual machine"`
		PermitWeakPCRBanks                  bool `long:"permit-weak-pcr-banks" description:"Permit selecting a weak PCR bank if no others are available"`
		PermitEmptyPCRBanks                 bool `long:"permit-empty-pcr-banks" description:"Allow the platform firmware to leave one or more PCR banks empty. This potentially compromises remote attestation"`
		PermitAddonDrivers                  bool `long:"permit-addon-drivers" description:"Allow addon drivers to be running. This increases fragility of profiles that include PCR2, and potentially PCR7"`
		PermitSysPrepApplications           bool `long:"permit-sys-prep-apps" description:"Allow system preparation applications to load before the OS. This increases fragility of profiles that include PCR4, and potentially PCR7"`
		PermitAbsolute                      bool `long:"permit-absolute" description:"Allow the Absolute endpoint management component to be running. This increases fragility of profiles that include PCR4"`
		PermitWeakSecureBootAlgorithms      bool `long:"permit-weak-secure-boot-algs" description:"Permit secure boot verification using weak algorithms"`
		PermitPreOSVerificationUsingDigests bool `long:"permit-preos-verification-using-digests" description:"Allow pre-OS components to be verified by including a digest in db. This increases fragility of profiles that include PCR7"`
		PermitInsufficientDMAProtection     bool `long:"permit-insufficient-dma-protection" description:"Permit environments that don't have sufficient DMA protection"`
	} `group:"Initial check options"`

	Profile struct {
		MostSecure                     bool `long:"most-secure" description:"Select the most secure PCR profile"`
		TrustCAsForBootCode            bool `long:"trust-authorities-for-boot-code" description:"Trust the secure boot CAs used to authenticate code on this system to authenticate any boot code (definitely not advisable for the Microsoft UEFI CA)"`
		TrustCAsForAddonDrivers        bool `long:"trust-authorities-for-addon-drivers" description:"Trust the secure boot CAs used to authenticate code on this system to authenticate any addon driver (most likely not advisable for the Microsoft UEFI CA)"`
		DistrustVARSuppliedNonHostCode bool `long:"distrust-var-supplied-nonhost-code" description:"Distrust code running in value-added-retailer supplied embedded controllers. This code doesn't run on the CPU and isn't part of the trust chain, but can potentially still affect trust"`
		PermitNoSecureBoot             bool `long:"permit-no-secure-boot" description:"Permit profiles that don't include the secure boot policy"`
		NoDiscreteTPMResetMitigation   bool `long:"no-discrete-tpm-reset-mitigation" description:"Disable mitigations against discrete TPM reset attacks where appropriate"`
	} `group:"PCR profile options"`

	Action preinstall.Action `long:"action" description:"What action to run"`

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
	if opts.Check.PermitWeakPCRBanks {
		checkFlags |= preinstall.PermitWeakPCRBanks
	}
	if opts.Check.PermitEmptyPCRBanks {
		checkFlags |= preinstall.PermitEmptyPCRBanks
	}
	if opts.Check.PermitAddonDrivers {
		checkFlags |= preinstall.PermitAddonDrivers
	}
	if opts.Check.PermitSysPrepApplications {
		checkFlags |= preinstall.PermitSysPrepApplications
	}
	if opts.Check.PermitAbsolute {
		checkFlags |= preinstall.PermitAbsoluteComputrace
	}
	if opts.Check.PermitWeakSecureBootAlgorithms {
		checkFlags |= preinstall.PermitWeakSecureBootAlgorithms
	}
	if opts.Check.PermitPreOSVerificationUsingDigests {
		checkFlags |= preinstall.PermitPreOSVerificationUsingDigests
	}
	if opts.Check.PermitInsufficientDMAProtection {
		checkFlags |= preinstall.PermitInsufficientDMAProtection
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

	var pcrFlags preinstall.PCRProfileOptionsFlags
	if opts.Profile.MostSecure {
		pcrFlags |= preinstall.PCRProfileOptionMostSecure
	}
	if opts.Profile.TrustCAsForBootCode {
		pcrFlags |= preinstall.PCRProfileOptionTrustCAsForBootCode
	}
	if opts.Profile.TrustCAsForAddonDrivers {
		pcrFlags |= preinstall.PCRProfileOptionTrustCAsForAddonDrivers
	}
	if opts.Profile.DistrustVARSuppliedNonHostCode {
		pcrFlags |= preinstall.PCRProfileOptionDistrustVARSuppliedNonHostCode
	}
	if opts.Profile.PermitNoSecureBoot {
		pcrFlags |= preinstall.PCRProfileOptionPermitNoSecureBootPolicyProfile
	}
	if opts.Profile.NoDiscreteTPMResetMitigation {
		pcrFlags |= preinstall.PCRProfileOptionNoPartialDiscreteTPMResetAttackMitigation
	}

	fmt.Println("Testing this platform for compatibility with EFI based TPM protected FDE")

	ctx := preinstall.NewRunChecksContext(checkFlags, bootImages, pcrFlags)
	result, err := ctx.Run(context.Background(), preinstall.ActionNone, nil)
	switch {
	case err != nil && opts.Action != preinstall.ActionNone:
		result, err = ctx.Run(context.Background(), opts.Action, nil)
		if err != nil {
			return err
		}
	case err != nil:
		return err
	}

	fmt.Printf("%v\n", result)

	profile := preinstall.WithAutoTCGPCRProfile(result, pcrFlags)
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
			fmt.Fprintln(os.Stderr, "This platform is not suitable for FDE:", err)
		}
	}
}
