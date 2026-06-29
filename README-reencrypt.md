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



- 
