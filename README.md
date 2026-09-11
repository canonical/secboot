# secboot

A Go library for managing TPM-backed encrypted disks on Linux operating systems.

## Features

- System installation & maintenance:
    * Do pre-install platform compatibility checks
    * Initialize the TPM
    * Seal a LUKS passphrase within the TPM
    * Update sealing policy (typically after platform or software update)
    * Manage TPM lockout (set authValue, reset)
    * Compute PCR profiles
    * Manage recovery keys of LUKS containers (create, list, delete)

- System boot:
    * Unseal
    * Attempt various unlocking paths (TPM-backed, with PIN, with passphrase,
      recovery...)

- Other useful functions
    * Get entropy of a PIN or passphrase
    * Access to UEFI variables PK, KEK, Db, Dbx


## Build

Prerequisites:
- go1.23 or later
- libkeyutils-dev

Build the standalone executables:
```
make build
```

## Test

```
make check
```

## License

Secboot is licensed under the GNU General Public License version 3.

See the [COPYING](COPYING) file for more details.
