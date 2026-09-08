package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/snapcore/secboot"
	"github.com/snapcore/secboot/log"
	_ "github.com/snapcore/secboot/luks2" // This gets the LUKS2 backend initialized
	"os"
	"strconv"
	"strings"
)

const Usage = `
Usage: 1. reencrypt [OPTIONS]              ACTIVE-NAME KEYSLOT-NAME:UNLOCK-KEY-HEX ...
       2. reencrypt [OPTIONS] --status     ACTIVE-NAME
       3. reencrypt [OPTIONS] --initialize ACTIVE-NAME KEYSLOT-NAME:UNLOCK-KEY-HEX ...
       4. reencrypt [OPTIONS] --resume     ACTIVE-NAME UNLOCK-KEY-HEX

Reencrypt an active encrypted container.

Options:
  --initialize   Only initialize reencryption
  --status       Only query the reencryption status
  --resume       Only resume reencryption
  -v, --verbose  Be verbose

For initializing reencryption, all unlock keys must be provided with
the name of their keyslot.

Arguments:
  ACTIVE-NAME     Name of the active volume as shown in /dev/mapper
  KEYSLOT-NAME    Name of the keyslot, as managed by secboot
  UNLOCK-KEY-HEX  Unlock key (hexadecimal)

Examples:
  cryptsetup open /dev/vda5 crypt01
  reencrypt --status crypt01
  reencrypt --initialize crypt01 default-recovery:010203... default:00112233...
  reencrypt --resume crypt01 010203...
`

var opts struct {
	// Slice of bool will append 'true' each time the option
	// is encountered (can be set multiple times, like -vvv)
	Verbose bool `short:"v" long:"verbose" description:"Show verbose debug information"`
	Help    bool `short:"h" long:"help" description:"Show help"`

	// Example of a required flag
	Initialize bool `long:"initialize" description:"Initialize"`
	Resume     bool `long:"resume" description:"Resume"`
	Status     bool `long:"status" description:"Get the reencryption status"`
}

func main() {

	if len(os.Args) <= 1 {
		fmt.Printf("%v\n", Usage)
		os.Exit(1)
	}

	var err error
	argParser := flags.NewParser(&opts, flags.PassDoubleDash)
	args, err := argParser.ParseArgs(os.Args[1:])

	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if opts.Help {
		fmt.Printf("%v\n", Usage)
		os.Exit(0)
	}

	if opts.Verbose {
		log.SetLogLevel(log.LogLevelDebug)
	} else {
		log.SetLogLevel(log.LogLevelInfo)
	}

	if opts.Status {
		err = cmdStatus(args...)
	} else if opts.Initialize {
		err = cmdInitialize(args...)
	} else if opts.Resume {
		err = cmdResume(args...)
	} else {
		err = cmdReencrypt(args...)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// splitUnlockKeySpec splits "KEY:VALUE" into "KEY" and "VALUE"
func splitUnlockKeySpec(s string) (string, string, error) {
	items := strings.Split(s, ":")
	if len(items) != 2 {
		return "", "", fmt.Errorf("invalid format KEY:VALUE")
	}
	return items[0], items[1], nil
}

func cmdReencrypt(args ...string) error {

	if len(args) < 2 {
		return fmt.Errorf("reencrypt: not enough arguments")
	}
	activeName := args[0]
	unlockKeysHex := args[1:] // remaining arguments

	log.Info("reencrypt %v with %v key(s)", activeName, len(unlockKeysHex))

	err := cmdStatus(activeName)
	if err != nil {
		return err
	}

	err = cmdInitialize(append([]string{activeName}, unlockKeysHex...)...)
	if err != nil {
		fmt.Printf("Cannot initialize reencryption of %v: %v\n", activeName, err)
		return err
	}

	// Resume using the first key of the list
	_, unlockKey, err := splitUnlockKeySpec(unlockKeysHex[0])
	if err != nil {
		// Should not happen, as already validated in initialize above
		return err
	}
	err = cmdResume(activeName, unlockKey)
	if err != nil {
		fmt.Printf("Cannot resume reencryption of %v: %v\n", activeName, err)
		return err
	}
	return nil
}

func cmdStatus(args ...string) error {
	if len(args) != 1 {
		return fmt.Errorf("status: bad argument count")
	}
	activeName := args[0]

	log.Debug("reencrypt status %v", activeName)

	reencryption, err := secboot.ReencryptionForActiveVolume(activeName)
	if err != nil {
		return err
	}

	status, err := reencryption.Status()
	if err != nil {
		return err
	}
	fmt.Println(status)
	return nil
}

func cmdInitialize(args ...string) error {
	if len(args) < 2 {
		return fmt.Errorf("initialize: missing argument")
	}

	activeName := args[0]
	unlockKeysHex := args[1:] // remaining arguments

	log.Info("reencrypt initialize %v", activeName)

	reencryption, err := secboot.ReencryptionForActiveVolume(activeName)
	if err != nil {
		return fmt.Errorf("Cannot find active volume: %w\n", err)
	}

	// Get unlock keys from format ["KEYSLOT-NAME:UNLOCK-KEY-HEX", ...]
	unlockKeys := make(map[string][]byte)
	anonymousKeyslotIndex := 0 // used to assign an index if keyslotName is empty
	for _, unlockKeySpec := range unlockKeysHex {
		// split name:hex into a map
		keyslotName, unlockKeyHex, err := splitUnlockKeySpec(unlockKeySpec)
		if err != nil {
			return err
		}
		if len(keyslotName) == 0 {
			// This is a key with no given keyslot name. Use the index.
			keyslotName = strconv.Itoa(anonymousKeyslotIndex)
			anonymousKeyslotIndex++
		}

		unlockKey, err := hex.DecodeString(unlockKeyHex)
		if err != nil {
			return fmt.Errorf("Malformed hex '%v': %w", unlockKeyHex, err)
		}
		unlockKeys[keyslotName] = unlockKey
	}

	err = reencryption.Initialize(context.Background(), unlockKeys)
	if err != nil {
		return fmt.Errorf("Cannot initialize: %w", err)
	}
	fmt.Println("Initialize: ok")
	return nil
}

func cmdResume(args ...string) error {
	if len(args) != 2 {
		return fmt.Errorf("resume: bad argument count")
	}

	activeName := args[0]
	unlockKeyHex := args[1]

	log.Info("reencrypt resume %v", activeName)
	unlockKey, err := hex.DecodeString(unlockKeyHex)
	if err != nil {
		return fmt.Errorf("Malformed hex '%v': %w", unlockKeyHex, err)
	}

	reencryption, err := secboot.ReencryptionForActiveVolume(activeName)
	if err != nil {
		fmt.Printf("Cannot find active volume: %v\n", err)
		return err
	}

	reencProgressChannel, err := reencryption.Resume(context.Background(), unlockKey)
	if err != nil {
		return fmt.Errorf("cannot resume: %w", err)
	}

	i := 0
	var msg secboot.ReencryptionProgressEvent
	for msg = range reencProgressChannel {
		i++
		switch msg.Type {
		case secboot.ReencryptionProgressCompleted:
			fmt.Printf("%v\n", msg.Type)
			return nil
		case secboot.ReencryptionProgressError:
			fmt.Printf("%v: %v\n", msg.Type, msg.Error)
			return fmt.Errorf("Reencryption failed")
		case secboot.ReencryptionProgressStarted:
			fmt.Printf("%v\n", msg.Type)
		case secboot.ReencryptionProgressRunning:
			fmt.Printf("%v: ", msg.Type)
			if msg.Error != nil {
				fmt.Printf("%v\n", msg.Error)
			} else {
				fmt.Printf("%v / %v\n", msg.Details.BytesReencryptedSoFar, msg.Details.DeviceSize)
			}
		}
	}
	return nil
}
