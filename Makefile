help:
	# Usage:
	# make build                  Build companion tools
	# make check                  Run all tests
	# make check-efi-preinstall   Run tests of package efi/preinstall
	# make check-efi              Run tests of package efi
	# make list-packages          List Go packages

# Disable optimization and inlining (to facilitate step-by-step debugging)
GCFLAGS = -gcflags "-N -l"

.PHONY: build check check-tpm2-simulator fmt FORCE
FORCE:

# Build command line programs
build: test_efi_fde_compat run_argon2 reencrypt secboot-tool

%: cmd/%/main.go FORCE
	go build -o $@ $(GCFLAGS) $<

check-tpm2-simulator:
	@echo "Checking installed snap: tpm2-simulator-chrisccoulson"
	@snap list tpm2-simulator-chrisccoulson > /dev/null

check: check-tpm2-simulator
	./run-tests --with-mssim

check-efi-preinstall.bin: FORCE
	go test -cover -c -o $@ $(GCFLAGS) ./efi/preinstall -v -ldflags '-X github.com/snapcore/secboot/internal/testenv.testBinary=enabled' -race -p 1

check-efi-preinstall: check-efi-preinstall.bin check-tpm2-simulator
	USE_MSSIM=1 ./$< -test.coverprofile=coverage.out -check.v
	# You may now view the coverage report by executing:
	#     go tool cover -func=coverage.out
	# or: go tool cover -html=coverage.out

check-efi.bin: FORCE
	go test -cover -c -o $@ $(GCFLAGS) ./efi -v -ldflags '-X github.com/snapcore/secboot/internal/testenv.testBinary=enabled' -race -p 1

check-efi: check-efi.bin check-tpm2-simulator
	@# cd to efi/. as testdata is expected in .
	cd efi && ../$< -test.coverprofile=coverage.out -check.v

fmt:
	go fmt ./...

list-packages:
	go list ./...
