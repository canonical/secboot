package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luksview"
	"github.com/snapcore/secboot/log"
	"github.com/snapcore/secboot/luks2"
	"github.com/snapcore/secboot/plainkey"
	"os"
)

const Usage = `
usage: 1. secboot-tool get-unlockkey-from-kernel DEVICE
       2. secboot-tool print-tokens DEVICE
       3. secboot-tool init-plainkey [--print-unlock-key] DEVICE PROTECTOR-KEY-HEX
       4. secboot-tool activate-plainkey DEVICE ACTIVE-NAME PROTECTOR-KEY-HEX
       5. secboot-tool deactivate DEVICE

Commands:
    init-plainkey
	Formats and initializes a LUKS device. An unlock key (ie: LUKS passphrase)
	is randomly generated and stored in the LUKS header, encrypted by the
	given PROTECTOR-KEY-HEX.
	If --print-unlock-key is given, the unlock key is printed to stdout.
`

func usage() {
	fmt.Print(Usage)
	os.Exit(1)
}

func main() {

	args := os.Args
	if len(args) <= 1 {
		usage()
	}

	log.SetLogLevel(log.LogLevelDebug)

	arg := args[1]
	args = args[2:] // pop 2 first items from the command line
	var err error
	switch arg {
	case "get-unlockkey-from-kernel":
		err = GetDiskUnlockKeyFromKernel(args)
	case "print-tokens":
		err = printTokens(args)
	case "init-plainkey":
		err = initContainerPlainkey(args)
	case "activate-plainkey":
		err = activateContainerPlainkey(args)
	case "deactivate":
		err = deactivateContainer(args)
	default:
		usage()
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func GetDiskUnlockKeyFromKernel(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("Bad argument count")
	}
	devicePath := args[0]
	unlockKey, err := secboot.GetDiskUnlockKeyFromKernel("ubuntu-fde", devicePath, false)
	if err != nil {
		return err
	}
	os.Stdout.Write(unlockKey)
	return nil
}

func printTokens(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("Bad argument count")
	}

	devicePath := args[0]

	view, err := luksview.NewView(context.Background(), devicePath)
	if err != nil {
		return err
	}
	format := "%-30v %-30v\n"
	fmt.Printf(format, "NAME", "TYPE")
	for _, name := range view.TokenNames() {
		token, _, _ := view.TokenByName(name)
		fmt.Printf(format, name, token.Type())
	}
	return nil
}

// Format an encrypted container and set up a "plainkey" token
func initContainerPlainkey(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("Bad arguments. Please provide DEVICE and ACTIVE-NAME.")
	}
	printUnlockKey := false
	if args[0] == "--print-unlock-key" {
		printUnlockKey = true
		args = args[1:] // consume the argument
	}

	if len(args) != 2 {
		return fmt.Errorf("Bad arguments. Please provide DEVICE and ACTIVE-NAME.")
	}

	devicePath := args[0]
	protectorKey, err := hex.DecodeString(args[1])
	if err != nil {
		return fmt.Errorf("PROTECTOR-KEY-HEX: %w", err)
	}

	keyData, _, unlockKey, err := plainkey.NewProtectedKey(rand.Reader, protectorKey, nil)
	if err != nil {
		return fmt.Errorf("cannot create protected key: %w", err)
	}

	if err := secboot.InitializeLUKS2Container(devicePath, "default-label", unlockKey, nil); err != nil {
		return fmt.Errorf("cannot initialize LUKS2 container: %w", err)
	}

	if printUnlockKey {
		fmt.Printf("%x\n", unlockKey)
	}

	tokenWriter, err := secboot.NewLUKS2KeyDataWriter(devicePath, "default")
	if err != nil {
		return fmt.Errorf("cannot create key data writer: %w", err)
	}
	if err := keyData.WriteAtomic(tokenWriter); err != nil {
		return fmt.Errorf("cannot write key data to container: %w", err)
	}
	return nil
}

// Activate an encrypted container protected by "plainkey" mechanism.
func activateContainerPlainkey(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("Bad arguments. Please provide DEVICE and ACTIVE-NAME")
	}
	devicePath := args[0]
	activeName := args[1]
	protectorKey, err := hex.DecodeString(args[2])
	if err != nil {
		return fmt.Errorf("PROTECTOR-KEY-HEX: %w", err)
	}

	log.SetLogLevel(log.LogLevelDebug)

	container, err := secboot.FindStorageContainer(context.Background(), devicePath)
	if err != nil {
		return fmt.Errorf("FindStorageContainer error: %w", err)
	}

	activateContext, err := secboot.NewActivateContext(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("NewActivateContext error: %w", err)
	}

	plainkey.SetProtectorKeys(protectorKey)

	var options []secboot.ActivateOption
	options = append(options, luks2.WithVolumeName(activeName))
	err = activateContext.ActivateContainer(context.Background(), container, options...)
	if err != nil {
		return fmt.Errorf("ActivateContainer error: %w", err)
	}
	return nil
}

func deactivateContainer(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("Bad argument count")
	}
	devicePath := args[0]

	log.SetLogLevel(log.LogLevelDebug)

	container, err := secboot.FindStorageContainer(context.Background(), devicePath)
	if err != nil {
		return fmt.Errorf("FindStorageContainer error: %w", err)
	}

	activateContext, err := secboot.NewActivateContext(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("NewActivateContext error: %w", err)
	}

	err = activateContext.DeactivateContainer(context.Background(), container, "secboot-tool")
	if err != nil {
		return fmt.Errorf("DeactivateContainer error: %w", err)
	}
	return nil
}
