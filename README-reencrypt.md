# Volume reencryption

Volume reencryption means rotating the encryption key.

The typical use cases are:

- The end user boots a factory installed encrypted image for the first time.
  They want to perform a re-encryption in order to rotate all key material in
  the absence of a lack of proof that keys were not extracted from the device in
  the factory environment.

- There is a change of owner of the computer.

Prerequisites:
- cryptsetup-bin with option `--keys-from-stdin-sizes`


## Testing

### Manual testing using `reencrypt`
```
FAST_PBKDF="--pbkdf-force-iterations 1000 --pbkdf pbkdf2"
dd if=/dev/zero count=2 of=disk.img bs=1G
sudo echo
LOOPDEV=$(sudo losetup -f)
sudo losetup $LOOPDEV disk.img
PWD1=$(echo -e "123\n456")
PWD2=$(echo -e "aaaa\nbbbb")
PWD3=$(echo -e "xx\nyy")
echo -n "$PWD1" | sudo cryptsetup luksFormat $LOOPDEV $FAST_PBKDF --key-file -
echo -n "${PWD1}${PWD2}" | sudo cryptsetup -q luksAddKey $LOOPDEV $FAST_PBKDF --key-file - --keyfile-size 7 -
echo -n "${PWD1}${PWD3}" | sudo cryptsetup -q luksAddKey $LOOPDEV $FAST_PBKDF --key-file - --keyfile-size 7 -

echo '{"type":"ubuntu-fde","keyslots":["0"],"ubuntu_fde_name":"default"}' | sudo cryptsetup token import $LOOPDEV
echo '{"type":"ubuntu-fde-recovery","keyslots":["1"],"ubuntu_fde_name":"default-recovery"}' | sudo cryptsetup token import $LOOPDEV
echo '{"type":"ubuntu-fde","keyslots":["2"],"ubuntu_fde_name":"default-fallback"}' | sudo cryptsetup token import $LOOPDEV

echo -n "$PWD1" | sudo cryptsetup open $LOOPDEV crypt01 --key-file -

sudo ./reencrypt crypt01 default:3132330a343536 default-recovery:616161610a62626262 default-fallback:78780a7979

sudo cryptsetup close crypt01

echo -n "${PWD1}" | sudo cryptsetup open $LOOPDEV --test-passphrase --key-file -
echo -n "${PWD2}" | sudo cryptsetup open $LOOPDEV --test-passphrase --key-file -
echo -n "${PWD3}" | sudo cryptsetup open $LOOPDEV --test-passphrase --key-file -

sudo cryptsetup luksDump $LOOPDEV --dump-json-metadata | jq .tokens
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

sudo losetup -d $LOOPDEV
```

## Manual testing with `secboot-tool`

### Setup
```
FAST_PBKDF="--pbkdf-force-iterations 1000 --pbkdf pbkdf2"
dd if=/dev/zero count=2 of=disk.img bs=1G
sudo echo
LOOPDEV=$(sudo losetup -f)
echo LOOPDEV=$LOOPDEV
sudo losetup $LOOPDEV disk.img
PWD1="0000"
echo -n "$PWD1" | sudo cryptsetup luksFormat $LOOPDEV $FAST_PBKDF --key-file -
cat << EOF | sudo cryptsetup token import $LOOPDEV
{
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
      "salt": "v/wrpFx5Ujz4TmUw6/wNvHY3V3rX6Oe2uPIcrnId5UU=",
      "nonce": "MRtlhutLiq3t6FJn",
      "protector-key-id": {
        "alg": "sha256",
        "salt": "aDZs+mB36c63Laxbq2QwOdiBOf43fIfOHYvYWCLFHM4=",
        "digest": "luLngXMjqznXAVbLERiSIiZX+1w2t+YdSZkhzJ888pA="
      }
    },
    "role": "",
    "kdf_alg": "sha256",
    "encrypted_payload": "45j/uRlEqBNb17YyoBGOtrc/yy9OMpPjemYgEuLk98JbEX1itmLM1O6FRtdIs6K/oeQje4lSyTmkFvnhZrN6o6EybipKkcEpG0yABNuOotPsgQPdxTw="
  }
}
EOF
```

### Test

```
dd if=/dev/zero count=2 of=disk.img bs=1G
sudo qemu-nbd -v -f raw -c /dev/nbd0 disk.img
```

(as root):
```
UNLOCK_KEY=$(./secboot-tool init-plainkey --print-unlock-key /dev/nbd0 30303030)
./secboot-tool activate-plainkey /dev/nbd0 crypt02 30303030
./reencrypt crypt02 default:$UNLOCK_KEY
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

./secboot-tool deactivate /dev/nbd0
```

### Teardown
```
sudo cryptsetup close crypt02
sudo losetup -d $LOOPDEV

```
```
- 
