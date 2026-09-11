# Volume reencryption

Volume reencryption means rotating the encryption key of the encrypted volume.

Typical use cases are:

- The end user boots a factory installed encrypted image for the first time.
  They want to perform a re-encryption in order to rotate all key material in
  the absence of proof that keys were not extracted from the device in
  the factory environment.

- There is a change of owner of the computer.

Prerequisites:

- `cryptsetup` supporting reencrypt option `--keys-from-stdin-sizes`


## API

The entry point for reencryption is: `ReencryptionForActiveVolume`.

See examples in `cmd/secboot-tool/reencrypt.go`.


## Testing

The following test scenarios use the `secboot-tool` testing tool and operate on
a crafted `disk.img` file.

### Test with protection mechanism "none"

Mechanism 'none' directly feeds the unlock key to the underlying LUKS2 container.

Setup:
```
DEVICE=disk.img
dd if=/dev/zero of=$DEVICE bs=1G count=2
UNLOCK_KEY_HEX=30303030303131313132323232333333333434343435353535363636363737373738383838

# Initialize the encrypted volume
./secboot-tool init $DEVICE $UNLOCK_KEY_HEX

# Basic checks with cryptsetup
echo -n 0000011112222333344445555666677778888 | cryptsetup open $DEVICE --test-passphrase --key-file -
cryptsetup luksDump $DEVICE --dump-json-metadata | jq .tokens
{
  "0": {
    "type": "ubuntu-fde",
    "keyslots": [
      "0"
    ],
    "ubuntu_fde_name": "default",
    "ubuntu_fde_priority": 0
  }
}
```

Reencrypt:
```
# Activate the encrypted volume
sudo ./secboot-tool activate $DEVICE crypt02 $UNLOCK_KEY_HEX

# Reencrypt
sudo ./secboot-tool reencrypt crypt02 default:$UNLOCK_KEY_HEX
reencrypt status crypt02
none
reencrypt initialize crypt02
reencrypt resume crypt02
started
running: 336592896 / 2140143616
running: 1009778688 / 2140143616
running: 1682964480 / 2140143616
running: 2140143616 / 2140143616
completed


# Deactivate
sudo cryptsetup close crypt02
```

### Test with protection mechanism "plainkey"

The plainkey mechanism (also called plainkey platform) is a way to store
the LUKS passphrase in a LUKS token, the passphrase being encrypted by a
protector key.

Setup:
```
# Initialize the encrypted volume with a protector key "0000"
DEVICE=disk.img
dd if=/dev/zero of=$DEVICE bs=1G count=2
UNLOCK_KEY_HEX=$(./secboot-tool init --print-unlock-key --mechanism plainkey $DEVICE 30303030)

# Basic checks with cryptsetup
echo $UNLOCK_KEY_HEX | xxd -revert -plain | cryptsetup open $DEVICE --test-passphrase --key-file -
cryptsetup luksDump $DEVICE --dump-json-metadata | jq .tokens
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

Reencrypt:
```
sudo ./secboot-tool activate --mechanism plainkey $DEVICE crypt02 30303030
sudo ./secboot-tool reencrypt crypt02 default:$UNLOCK_KEY_HEX
reencrypt status crypt02
none
reencrypt initialize crypt02
reencrypt resume crypt02
started
running: 336592896 / 2140143616
running: 1009778688 / 2140143616
running: 1682964480 / 2140143616
running: 2140143616 / 2140143616
completed

# Deactivate
sudo cryptsetup close crypt02
```

### Test with multiple keyslots

Setup:
```
# Initialize the encrypted volume
DEVICE=disk.img
dd if=/dev/zero of=$DEVICE bs=1G count=2
PWD1=$(echo -e "123\n456")
echo -n "$PWD1" | cryptsetup luksFormat $DEVICE --key-file -

# Add 2 other keys
PWD2=$(echo -e "aaaa\nbbbb")
echo -n "${PWD1}${PWD2}" | cryptsetup -q luksAddKey $DEVICE --key-file - --keyfile-size 7 -

PWD3=$(echo -e "xx\nyy")
echo -n "${PWD1}${PWD3}" | cryptsetup -q luksAddKey $DEVICE --key-file - --keyfile-size 7 -

# Add named tokens so that secboot can find them
echo '{"type":"ubuntu-fde","keyslots":["0"],"ubuntu_fde_name":"default"}' | cryptsetup token import $DEVICE
echo '{"type":"ubuntu-fde-recovery","keyslots":["1"],"ubuntu_fde_name":"default-recovery"}' | cryptsetup token import $DEVICE
echo '{"type":"ubuntu-fde","keyslots":["2"],"ubuntu_fde_name":"default-fallback"}' | cryptsetup token import $DEVICE
```

Reencrypt:
```
echo -n "$PWD1" | sudo cryptsetup open $DEVICE crypt02 --key-file -

sudo ./secboot-tool reencrypt crypt02 default:3132330a343536 default-recovery:616161610a62626262 default-fallback:78780a7979
reencrypt status crypt02
none
reencrypt initialize crypt02
reencrypt resume crypt02
started
running: 336592896 / 2140143616
running: 1009778688 / 2140143616
running: 1682964480 / 2140143616
running: 2140143616 / 2140143616
completed

sudo cryptsetup close crypt02
```

Check that all 3 keyslots have been retained:
```
echo -n "${PWD1}" | cryptsetup open $DEVICE --test-passphrase --key-file -
echo -n "${PWD2}" | cryptsetup open $DEVICE --test-passphrase --key-file -
echo -n "${PWD3}" | cryptsetup open $DEVICE --test-passphrase --key-file -

cryptsetup luksDump $DEVICE --dump-json-metadata | jq .tokens
{
  "0": {
    "type": "ubuntu-fde",
    "keyslots": [
      "3"
    ],
    "ubuntu_fde_name": "default"
  },
  "1": {
    "type": "ubuntu-fde-recovery",
    "keyslots": [
      "4"
    ],
    "ubuntu_fde_name": "default-recovery"
  },
  "2": {
    "type": "ubuntu-fde",
    "keyslots": [
      "5"
    ],
    "ubuntu_fde_name": "default-fallback"
  }
}
```
