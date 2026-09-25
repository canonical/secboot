package main

import (
	"context"
	"fmt"
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luksview"
	"os"
)

func cmdGetDiskUnlockKeyFromKernel(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("bad argument count\nusage: seboot-tool get-unlockkey-from-kernel <device-path>")
	}
	devicePath := args[0]
	unlockKey, err := secboot.GetDiskUnlockKeyFromKernel("ubuntu-fde", devicePath, false)
	if err != nil {
		return err
	}
	os.Stdout.Write(unlockKey)
	return nil
}

func cmdPrintTokens(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("bad argument count\nusage: seboot-tool print-tokens <device-path>")
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
