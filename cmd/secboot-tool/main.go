package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const Usage = `
usage: secboot-tool <command> ...

Commands:
    init                      Initialize (format) an encrypted container
    activate                  Activate (open) an encrypted container
    deactivate                Deactivate (close) an encrypted container	
    get-unlockkey-from-kernel Get an unlock key from the kernel's keyring
    print-tokens              Print tokens of a LUKS2 device
`

func die(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		die(Usage)
	}

	arg := args[0]  // command name
	args = args[1:] // pop command name from the command line args
	var err error
	switch arg {
	case "get-unlockkey-from-kernel":
		err = cmdGetDiskUnlockKeyFromKernel(args)
	case "print-tokens":
		err = cmdPrintTokens(args)
	case "init":
		err = cmdInitContainer(args)
	case "activate":
		err = cmdActivateContainer(args)
	case "deactivate":
		err = cmdDeactivateContainer(args)
	case "reencrypt":
		err = cmdReencrypt(args)
	default:
		die(Usage)
	}
	if err != nil {
		die(err.Error())
	}
}

// Get lines from stdin and trim spaces
func getLinesFromStdin() ([]string, error) {
	lines := []string{}
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		if len(line) > 0 {
			lines = append(lines, strings.TrimSpace(line))
		}
		if err == io.EOF {
			break // end of stream
		}
	}
	return lines, nil
}
