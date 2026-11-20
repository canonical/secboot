package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/jessevdk/go-flags"
	"os"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/log"

	"github.com/snapcore/secboot/plainkey"
)

const UsageInit = `
usage: secboot-tool init [<options>] <device> <unlock-key-hex>

Initialize (format) an encrypted container with the 'plainkey' mechanism.

Options:
  -m, --mechanism <mechanism>
                 Select a mechanism for key protection (see below)
  --print-unlock-key
                 Print the unlock key (for test and debug only)

  -h, --help     Show this help message
  -v, --verbose  Be verbose

Arguments:
  <device>         Path to an encrypted container
  <unlock-key-hex> Unlock key (hexadecimal)

Mechanisms:
  none
      The given <unlock-key-hex> is used directly as the LUKS passphrase.
      This is the default.
  plainkey
      An LUKS passphrase is randomly generated and stored in the
      LUKS header, encrypted by the given <unlock-key-hex>.

Examples:
  secboot-tool init /dev/sda1 30303030303131313132323232333333333434343435353535363636363737373738383838
`

var optsInit struct {
	Mechanism      string `short:"m" long:"mechanism" description:"Mechanism for key protection" required:"false" default:"none"`
	PrintUnlockKey bool   `short:"p" long:"print-unlock-key" description:"Print generated unlock key"`
	Verbose        bool   `short:"v" long:"verbose" description:"Show debug information"`
	Help           bool   `short:"h" long:"help" description:"Show help"`
}

func cmdInitContainerPlainkey(args []string) error {
	var err error
	argParser := flags.NewParser(&optsInit, flags.PassDoubleDash)
	positionalArgs, err := argParser.ParseArgs(args)

	if err != nil {
		return err
	}

	if optsInit.Help || len(positionalArgs) == 0 {
		fmt.Printf("%v\n", UsageInit)
		os.Exit(0)
	}

	if optsInit.Verbose {
		log.SetLogLevel(log.LogLevelDebug)
	} else {
		log.SetLogLevel(log.LogLevelInfo)
	}

	printUnlockKey := false
	if optsInit.PrintUnlockKey {
		printUnlockKey = true
	}

	if len(positionalArgs) != 2 {
		return fmt.Errorf("bad argument count")
	}

	devicePath := positionalArgs[0]
	protectorKey, err := hex.DecodeString(positionalArgs[1])
	if err != nil {
		return fmt.Errorf("bad unlok-key-hex: %w", err)
	}

	keyslotName := "default"
	initLUKSopts := &secboot.InitializeLUKS2ContainerOptions{
		MetadataKiBSize:     2048,
		KeyslotsAreaKiBSize: 2560,
		InlineCryptoEngine:  false,
		InitialKeyslotName:  keyslotName,
	}

	var keyData *secboot.KeyData
	var unlockKey []byte
	switch optsInit.Mechanism {
	case "plainkey":
		keyData, _, unlockKey, err = plainkey.NewProtectedKey(rand.Reader, protectorKey, nil)
		if err != nil {
			return fmt.Errorf("cannot create protected key: %w", err)
		}
	case "none":
		unlockKey = protectorKey
	default:
		return fmt.Errorf("invalid mechanism")
	}

	log.Debugf("using mechanism: %v", optsInit.Mechanism)

	if err := secboot.InitializeLUKS2Container(devicePath, "default-label", unlockKey, initLUKSopts); err != nil {
		return fmt.Errorf("cannot initialize LUKS2 container: %w", err)
	}

	if printUnlockKey {
		fmt.Printf("%x\n", unlockKey)
	}

	if optsInit.Mechanism == "plainkey" {
		tokenWriter, err := secboot.NewLUKS2KeyDataWriter(devicePath, keyslotName)
		if err != nil {
			return fmt.Errorf("cannot create key data writer: %w", err)
		}
		if err := keyData.WriteAtomic(tokenWriter); err != nil {
			return fmt.Errorf("cannot write key data to container: %w", err)
		}
	}
	return nil
}
