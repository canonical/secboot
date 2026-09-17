package main

import (
	"context"
	"fmt"
	"github.com/jessevdk/go-flags"
	"os"

	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/log"
)

const UsageDeactivate = `
usage: secboot-tool deactivate [<options>] <active-name>

Deactivate an active encrypted container.

Options:
  -h, --help	 Show this help message
  -v, --verbose  Be verbose

Arguments:
  <active-name>    Name of the active volume as shown in /dev/mapper

Examples:
  secboot-tool deactivate crypt02
`

var optsDeactivate struct {
	Verbose bool `short:"v" long:"verbose" description:"Show debug information"`
	Help    bool `short:"h" long:"help" description:"Show help"`
}

func cmdDeactivateContainer(args []string) error {
	var err error
	argParser := flags.NewParser(&optsDeactivate, flags.PassDoubleDash)
	positionalArgs, err := argParser.ParseArgs(args)

	if err != nil {
		return err
	}

	if optsDeactivate.Help || len(positionalArgs) == 0 {
		fmt.Printf("%v\n", UsageDeactivate)
		os.Exit(0)
	}

	if optsDeactivate.Verbose {
		log.SetLogLevel(log.LogLevelDebug)
	} else {
		log.SetLogLevel(log.LogLevelInfo)
	}

	if len(positionalArgs) != 1 {
		return fmt.Errorf("Bad argument count")
	}
	devicePath := positionalArgs[0]

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
