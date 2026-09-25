# Volume reencryption

Volume reencryption means rotating the encryption key of the encrypted volume.

The typical use cases are:

- The end user boots a factory installed encrypted image for the first time.
  They want to perform a re-encryption in order to rotate all key material in
  the absence of proof that keys were not extracted from the device in
  the factory environment.

- There is a change of owner of the computer.

Prerequisites:

- cryptsetup-bin with option `--keys-from-stdin-sizes`


## Testing

### Using `cryptsetup` and `secboot-tool reencrypt`

To accelerate testing, set pbkdf iterations to a very low number (do not do that in production as it weakens security!):
```
FAST_PBKDF="--pbkdf-force-iterations 1000 --pbkdf pbkdf2"
```

Initialize local empty disk image and encrypt it with 3 keyslots:
```
DEVICE=disk.img
dd if=/dev/zero count=2 of=$DEVICE bs=1G
PWD1=$(echo -e "123\n456")
PWD2=$(echo -e "aaaa\nbbbb")
PWD3=$(echo -e "xx\nyy")
echo -n "$PWD1" | sudo cryptsetup luksFormat $DEVICE $FAST_PBKDF --key-file -
echo -n "${PWD1}${PWD2}" | sudo cryptsetup -q luksAddKey $DEVICE $FAST_PBKDF --key-file - --keyfile-size 7 -
echo -n "${PWD1}${PWD3}" | sudo cryptsetup -q luksAddKey $DEVICE $FAST_PBKDF --key-file - --keyfile-size 7 -

echo '{"type":"ubuntu-fde","keyslots":["0"],"ubuntu_fde_name":"default"}' | sudo cryptsetup token import $DEVICE
echo '{"type":"ubuntu-fde-recovery","keyslots":["1"],"ubuntu_fde_name":"default-recovery"}' | sudo cryptsetup token import $DEVICE
echo '{"type":"ubuntu-fde","keyslots":["2"],"ubuntu_fde_name":"default-fallback"}' | sudo cryptsetup token import $DEVICE

echo -n "$PWD1" | sudo cryptsetup open $DEVICE crypt01 --key-file -
```

Perform reencryption using `secboot-tool`:
```
sudo ./secboot-tool reencrypt crypt01 default:3132330a343536 default-recovery:616161610a62626262 default-fallback:78780a7979
```

Close and check that all 3 keyslots have been retained:
```
sudo cryptsetup close crypt01

echo -n "${PWD1}" | sudo cryptsetup open $DEVICE --test-passphrase --key-file -
echo -n "${PWD2}" | sudo cryptsetup open $DEVICE --test-passphrase --key-file -
echo -n "${PWD3}" | sudo cryptsetup open $DEVICE --test-passphrase --key-file -

sudo cryptsetup luksDump $DEVICE --dump-json-metadata | jq .tokens
{
  "0": {
    "type": "example0",
    "keyslots": [
      "3"
    ],
    "ubuntu_fde_name": "default"
  },
  "1": {
    "type": "example1",
    "keyslots": [
      "4"
    ],
    "ubuntu_fde_name": "default-recovery"
  },
  "2": {
    "type": "example2",
    "keyslots": [
      "5"
    ],
    "ubuntu_fde_name": "default-fallback"
  }
}
```

### Test using `secboot-tool` and the "plainkey" mechanism

Initialize and empty encrypted image with the "plainkey" mechanism:
```
DEVICE=disk.img
dd if=/dev/zero count=2 of=$DEVICE bs=1G
UNLOCK_KEY=$(./secboot-tool init --print-unlock-key $DEVICE 30303030)
```

Run (as root):
```
./secboot-tool activate $DEVICE crypt02 30303030
./secboot-tool reencrypt crypt02 default:$UNLOCK_KEY
...
started
running: 115343360 / 2130706432
running: 241172480 / 2130706432
running: 367001600 / 2130706432
running: 492830720 / 2130706432
running: 608174080 / 2130706432
running: 723517440 / 2130706432
running: 849346560 / 2130706432
running: 975175680 / 2130706432
running: 1101004800 / 2130706432
running: 1226833920 / 2130706432
running: 1352663040 / 2130706432
running: 1478492160 / 2130706432
running: 1593835520 / 2130706432
running: 1719664640 / 2130706432
running: 1835008000 / 2130706432
running: 1950351360 / 2130706432
running: 2065694720 / 2130706432
running: 2130706432 / 2130706432
completed
```

Note: using `./secboot-tool deactivate disk.img` does not work as it needs a
block device (which `disk.img` is not).

Teardown:
```
sudo cryptsetup close crypt02
```

### Annex: details of the "plainkey" mechanism

The "plainkey" mechanism (also called "plainkey" platform) is a way to store
the LUKS passphrase in a LUKS token, the passphrase being encrypted by a
protector key. It can be used in production provided that the protector key
itself is protected by another mechanism (eg: by the "tpm2" mechanism).

After initialization by the `secboot-tool init` command (see above), it looks like this:
```
DEVICE=disk.img
sudo cryptsetup luksDump $DEVICE --dump-json-metadata | jq .tokens
{
  "0": {
    "type": "ubuntu-fde",
    "keyslots": [
      "1"
    ],
    "ubuntu_fde_name": "default",
    "ubuntu_fde_priority": 0,
    "ubuntu_fde_data": {
      "generation": 2,
      "platform_name": "plainkey",
      "platform_handle": {
        "version": 1,
        "salt": "N5hJAUvthtLRhb9AwBaV6MJuI/m7160o+KCMAPfAX3A=",
        "nonce": "Cwe8G/Q4ZlJhxMzr",
        "protector-key-id": {
          "alg": "sha256",
          "salt": "PqpOSf1lwi5iqb2oV3nVZiFGTL3poYUQe+9nKAmn7UM=",
          "digest": "AmsV628V8yB9PiZv1yCKu5XCWKdWL3GfqSXdo+qdTP0="
        }
      },
      "role": "",
      "kdf_alg": "sha256",
      "encrypted_payload": "RphJz+O/9pn4NeaadPt1DZZI1pjzBVrP8EHnNuPHGwyP7aztFeGssdAESlKZK7+MuB3AAt8Wd6JUB/7gCLXXs0kbnMV6jgB9Zy/UkMsMlF2OsUcymoM="
    }
  }
}
```
