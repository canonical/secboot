package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/log"

	"github.com/snapcore/secboot/luks2"
	"github.com/snapcore/secboot/plainkey"
)

const UsageActivate = `
usage: secboot-tool activate [<options>] <device> <active-name>

Activate an encrypted container.
The unlock key must be given in hexadecimal on stdin (<unlock-key-hex>).

Options:
  -m, --mechanism <mechanism>
                Select a mechanism for key protection (see secboot-tool init)
  -h, --help    Show this help message
  -v, --verbose Be verbose

Arguments:
  <active-name>    Name of the active volume as shown in /dev/mapper
  <device>         Path to an encrypted container

Examples:
  echo 30303030 | secboot-tool activate /dev/sda1 crypt02
`

var optsActivate struct {
	Mechanism string `short:"m" long:"mechanism" description:"Mechanism for key protection" required:"false" default:"none" choice:"none" choice:"plainkey"`
	Verbose   bool   `short:"v" long:"verbose" description:"Show debug information"`
	Help      bool   `short:"h" long:"help" description:"Show help"`
}

func cmdActivateContainer(args []string) error {
	var err error
	argParser := flags.NewParser(&optsActivate, flags.PassDoubleDash)
	positionalArgs, err := argParser.ParseArgs(args)

	if err != nil {
		return err
	}

	if optsActivate.Help || len(positionalArgs) == 0 {
		fmt.Printf("%v\n", UsageActivate)
		os.Exit(0)
	}

	if optsActivate.Verbose {
		log.SetLogLevel(log.LogLevelDebug)
	} else {
		log.SetLogLevel(log.LogLevelInfo)
	}

	if len(positionalArgs) != 2 {
		return fmt.Errorf("bad argument count")
	}
	devicePath := positionalArgs[0]
	activeName := positionalArgs[1]

	lines, err := getLinesFromStdin()
	if err != nil {
		return fmt.Errorf("cannot get key from stdin: %w", err)
	}
	if len(lines) == 0 {
		return fmt.Errorf("cannot get key from stdin (empty)")
	}
	protectorKey, err := hex.DecodeString(lines[0])
	if err != nil {
		return fmt.Errorf("bad <unlock-key-hex>: %w", err)
	}

	log.Debugf("using mechanism: %v", optsActivate.Mechanism)

	container, err := secboot.FindStorageContainer(context.Background(), devicePath)
	if err != nil {
		return fmt.Errorf("findStorageContainer error: %w", err)
	}

	activateContext, err := secboot.NewActivateContext(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("NewActivateContext error: %w", err)
	}

	if optsActivate.Mechanism == "plainkey" {
		plainkey.SetProtectorKeys(protectorKey)
	}

	var options []secboot.ActivateOption
	options = append(options, luks2.WithVolumeName(activeName))

	if optsActivate.Mechanism == "none" {
		options = append(options, secboot.WithExternalUnlockKey("secboot-tool", protectorKey, 0))
	}

	err = activateContext.ActivateContainer(context.Background(), container, options...)
	if err != nil {
		return fmt.Errorf("ActivateContainer error: %w", err)
	}
	return nil
}
