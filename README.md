## secboot 

A go module for secure boot support.

## Purpose & Description

Ubuntu Core support secure boot out-of-the box. This functionality is provided by snapd. Snapd internally uses this go module to provide secure boot functionality.

## Target Audience 

Snapd & Ubuntu Core developers

## Target Platforms / Devices / Hardware 

Any device that supports secure boot (with a TPM), such as:
- Intel NUCs with Intel PTT (fTPM)
- Arm SBC's with dTPM

## Building & Installation

This is a go module, it can't be built as standalone binary.

## Testing

Execute ``` ./run-tests``` 

## Architecture and Code structure

Describe code structure, external dependencies...etc

```tree
.
├── efi   ---> This directory holds XXX related code
├── internal ---> This directory holds XXX related code
├── tools
├── tpm2
├── vendor
├── CONTRIBUTING.md
├── crypt.go
├── crypt_test.go
├── export_test.go
├── get-deps
├── HACKING.md
├── keydata_file.go
├── keydata_file_test.go
├── keydata.go
├── keydata_test.go
├── keyring.go
├── keyring_test.go
├── platform.go
├── README.md
├── run-tests
├── secboot_test.go
└── snap.go
```

## Contributing

See [Contributing](CONTRIBUTING)

## License

See [License](LICENSE)

