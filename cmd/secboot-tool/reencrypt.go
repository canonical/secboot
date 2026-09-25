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

const UsageReencrypt = `
usage: secboot-tool reencrypt [<options>] <active-name>
                              [<keyslot-name>:<unlock-key-hex> ...] [<unlock-key-hex>]

Reencrypt an active encrypted container.

To initialize reencryption, the unlock keys of all keyslots must be given,
with the name of their keyslot.

For resuming an already initialized reencryption, one <unlock-key-hex>
must be given.

Options:
  --initialize   Only initialize reencryption
  --resume       Only resume reencryption
  --status       Only query the reencryption status
  
  -h, --help	 Show this help message
  -v, --verbose  Be verbose

Arguments:
  <active-name>    Name of the active volume as shown in /dev/mapper
  <keyslot-name>  Name of the keyslot, as managed by secboot
  <unlock-key-hex> Unlock key (hexadecimal)

Examples:
  cryptsetup open /dev/vda5 crypt01
  secboot-tool reencrypt --status crypt01
  secboot-tool reencrypt --initialize crypt01 default-recovery:010203 default:00112233
  secboot-tool reencrypt --resume crypt01 010203
`

var optsReencrypt struct {
	// Slice of bool will append 'true' each time the option
	// is encountered (can be set multiple times, like -vvv)
	Verbose bool `short:"v" long:"verbose" description:"Show verbose debug information"`
	Help    bool `short:"h" long:"help" description:"Show help"`

	// Example of a required flag
	Initialize bool `long:"initialize" description:"Initialize"`
	Resume     bool `long:"resume" description:"Resume"`
	Status     bool `long:"status" description:"Get the reencryption status"`
}

func cmdReencrypt(args []string) error {
	var err error
	argParser := flags.NewParser(&optsReencrypt, flags.PassDoubleDash)
	positionalArgs, err := argParser.ParseArgs(args)

	if err != nil {
		return err
	}

	if optsReencrypt.Help || len(positionalArgs) == 0 {
		fmt.Printf("%v\n", UsageReencrypt)
		os.Exit(0)
	}

	if optsReencrypt.Verbose {
		log.SetLogLevel(log.LogLevelDebug)
	} else {
		log.SetLogLevel(log.LogLevelInfo)
	}

	if optsReencrypt.Status {
		err = reencryptStatus(positionalArgs...)
	} else if optsReencrypt.Initialize {
		err = reencryptInitialize(positionalArgs...)
	} else if optsReencrypt.Resume {
		err = reencryptResume(positionalArgs...)
	} else {
		err = reencryptInitResume(positionalArgs...)
	}

	if err != nil {
		return err
	}
	return nil
}

// splitUnlockKeySpec splits "KEY:VALUE" into "KEY" and "VALUE"
func splitUnlockKeySpec(s string) (string, string, error) {
	items := strings.Split(s, ":")
	if len(items) != 2 {
		return "", "", fmt.Errorf("invalid format KEY:VALUE")
	}
	return items[0], items[1], nil
}

func reencryptInitResume(args ...string) error {

	if len(args) < 2 {
		return fmt.Errorf("reencrypt: not enough arguments")
	}
	activeName := args[0]
	unlockKeysHex := args[1:] // remaining arguments

	log.Infof("reencrypt %v with %v key(s)", activeName, len(unlockKeysHex))

	err := reencryptStatus(activeName)
	if err != nil {
		return err
	}

	err = reencryptInitialize(append([]string{activeName}, unlockKeysHex...)...)
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
	err = reencryptResume(activeName, unlockKey)
	if err != nil {
		fmt.Printf("Cannot resume reencryption of %v: %v\n", activeName, err)
		return err
	}
	return nil
}

func reencryptStatus(args ...string) error {
	if len(args) != 1 {
		return fmt.Errorf("status: bad argument count")
	}
	activeName := args[0]

	log.Debugf("reencrypt status %v", activeName)

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

func reencryptInitialize(args ...string) error {
	if len(args) < 2 {
		return fmt.Errorf("initialize: missing argument")
	}

	activeName := args[0]
	unlockKeysHex := args[1:] // remaining arguments

	log.Infof("reencrypt initialize %v", activeName)

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

func reencryptResume(args ...string) error {
	if len(args) != 2 {
		return fmt.Errorf("resume: bad argument count")
	}

	activeName := args[0]
	unlockKeyHex := args[1]

	log.Infof("reencrypt resume %v", activeName)
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
