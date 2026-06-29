package main

import (
	"context"
	"fmt"
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/internal/luksview"
	"github.com/snapcore/secboot/log"
	"os"
)

const Usage = `
usage: 1. secboot-tool GetDiskUnlockKeyFromKernel DEVICE
       2. secboot-tool print-tokens DEVICE
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
	switch arg {
	case "GetDiskUnlockKeyFromKernel":
		if len(args) == 0 {
			usage()
		}
		GetDiskUnlockKeyFromKernel(args[0])
	case "print-tokens":
		if len(args) == 0 {
			usage()
		}
		printTokens(args[0])
	default:
		usage()
	}
}

func GetDiskUnlockKeyFromKernel(devicePath string) {
	fmt.Println("GetDiskUnlockKeyFromKernel")
	unlockKey, err := secboot.GetDiskUnlockKeyFromKernel("ubuntu-fde", devicePath, false)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Stdout.Write(unlockKey)
	fmt.Println("---")
}

func printTokens(devicePath string) {
	view, err := luksview.NewView(context.Background(), devicePath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	format := "%-30v %-30v\n"
	fmt.Printf(format, "NAME", "TYPE")
	for _, name := range view.TokenNames() {
		token, _, _ := view.TokenByName(name)
		fmt.Printf(format, name, token.Type())
	}
}
