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
- `secboot-tool` (see [Build](./README.md#build))


## API

The entry point for reencryption is: `ReencryptionForActiveVolume`.

See examples in `cmd/secboot-tool/reencrypt.go`.


## Testing

The following test scenarios use the `secboot-tool` testing tool and operate on
a crafted `disk.img` file.

### Test with protection mechanism "none"

Mechanism "none" directly feeds the unlock key to the underlying LUKS2 container.

- Setup:
```
DEVICE=disk.img
dd if=/dev/zero of=$DEVICE bs=1G count=2
UNLOCK_KEY_HEX=30303030303131313132323232333333333434343435353535363636363737373738383838

# Initialize the encrypted volume
echo $UNLOCK_KEY_HEX | ./secboot-tool init $DEVICE

# Basic checks with cryptsetup
echo -n 0000011112222333344445555666677778888 | cryptsetup open $DEVICE --test-passphrase --key-file -
cryptsetup luksDump $DEVICE --dump-json-metadata | jq .tokens
```
You should get something like this printed:
```json
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

- Reencrypt:
```
# Activate the encrypted volume
echo $UNLOCK_KEY_HEX | sudo ./secboot-tool activate $DEVICE crypt02

# Reencrypt
echo default:$UNLOCK_KEY_HEX | sudo ./secboot-tool reencrypt crypt02
```
You should get something like this printed:
```
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
```

- Deactivate:
```
sudo ./secboot-tool deactivate crypt02
```

### Test with protection mechanism "plainkey"

The plainkey mechanism (also called plainkey platform) is a way to store
the LUKS passphrase in a LUKS token, the passphrase being encrypted by a
protector key.

- Setup:
```
# Initialize the encrypted volume with a protector key "0000"
DEVICE=disk.img
dd if=/dev/zero of=$DEVICE bs=1G count=2
UNLOCK_KEY_HEX=$(echo 30303030 | ./secboot-tool init --print-unlock-key --mechanism plainkey $DEVICE)

# Basic checks with cryptsetup
echo $UNLOCK_KEY_HEX | xxd -revert -plain | cryptsetup open $DEVICE --test-passphrase --key-file -

cryptsetup luksDump $DEVICE --dump-json-metadata | jq .tokens
```
You should get something like this printed:
```json
{
  "0": {
    "type": "ubuntu-fde",
    "keyslots": [
      "0"
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

- Reencrypt:
```
echo 30303030 | sudo ./secboot-tool activate --mechanism plainkey $DEVICE crypt02
echo default:$UNLOCK_KEY_HEX | sudo ./secboot-tool reencrypt crypt02
```
You should get something like this printed:
```
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
```

- Deactivate:
```
sudo ./secboot-tool deactivate crypt02
```

### Test with multiple keyslots

- Setup:
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

- Reencrypt:
```
echo -n "$PWD1" | sudo cryptsetup open $DEVICE crypt02 --key-file -

sudo ./secboot-tool reencrypt crypt02 << EOF
default:3132330a343536
default-recovery:616161610a62626262
default-fallback:78780a7979
EOF
```
You should get something like this printed:
```
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
```

- Deactivate:
```
sudo ./secboot-tool deactivate crypt02
```

- Check that all 3 keyslots have been retained:
```
echo -n "${PWD1}" | cryptsetup open $DEVICE --test-passphrase --key-file -
echo -n "${PWD2}" | cryptsetup open $DEVICE --test-passphrase --key-file -
echo -n "${PWD3}" | cryptsetup open $DEVICE --test-passphrase --key-file -

cryptsetup luksDump $DEVICE --dump-json-metadata | jq .tokens
```
You should get something like this printed:
```json
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

## Mapping leftovers on hard interruption

If reencryption gets interrupted the system may have leftover device-mapper
volumes with `-overlay` and `-hotzone-forward` suffixes.

This section shows how to reproduce this case and how to deal with it.

- Initialize a file-backed device for testing:
```
DEVICE=disk.img
dd if=/dev/zero of=$DEVICE bs=1G count=2
UNLOCK_KEY_HEX=30303030303131313132323232333333333434343435353535363636363737373738383838

# Initialize the encrypted volume
echo $UNLOCK_KEY_HEX | ./secboot-tool init $DEVICE

# Activate the encrypted volume
echo $UNLOCK_KEY_HEX | sudo ./secboot-tool activate $DEVICE crypt02
```

- Print the mapping (device numbers may differ):
```
sudo dmsetup ls | grep crypt02

sudo dmsetup table | grep crypt02
```
You should get something like this printed:
```
crypt02	(252:2)
crypt02: 0 4179968 crypt aes-xts-plain64 :64:logon:cryptsetup:500ea526-73ef-447a-89ca-12da35e5bcc0-d0 0 7:42 14336 1 sector_size:4096
```

- Start reencrypting, and while the `running:...` lines are being printed,
  interrupt with Control-Z (then `kill -KILL %1` if needed):
```
echo default:$UNLOCK_KEY_HEX | sudo ./secboot-tool reencrypt crypt02
```
you should get something like this printed:
```
reencrypt status crypt02
none
reencrypt initialize crypt02
reencrypt resume crypt02
started
running: 336592896 / 2140143616
running: 1009778688 / 2140143616
^ZKilled
```

- Print the mapping:
```
sudo dmsetup ls | grep crypt02
```
You should get something like this:
```
crypt02 (252:2)
crypt02-hotzone-forward (252:3)
crypt02-overlay (252:4)
```
... then:
```
sudo dmsetup table | grep crypt02
```
You should get something like this:
```
crypt02: 0 4179968 linear 252:4 0
crypt02-hotzone-forward: 0 4179968 linear 7:42 14336
crypt02-overlay: 0 3944448 crypt aes-xts-plain64 :64:logon:cryptsetup:2b215955-049e-41de-9914-26c166ebf197-d0 0 7:42 14336 1 sector_size:4096
crypt02-overlay: 3944448 235520 crypt aes-xts-plain64 :64:logon:cryptsetup:2b215955-049e-41de-9914-26c166ebf197-d0 3944448 252:3 3944448 1 sector_size:4096
```

- Deactivate the top-level volume `crypt02`
```
sudo ./secboot-tool deactivate crypt02
```

- Nothing is left active:
```
sudo dmsetup ls | grep crypt02
sudo dmsetup table | grep crypt02
```
