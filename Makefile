help:
	# Usage:
	# make build                  Build companion tools (cmd/)
	# make check                  Run all tests
	# make <pkg>                  Run tests of a specific package
	#                             (eg: make secboot, make efi/preinstall)
	# make list-packages          List Go packages (excluding cmd and tools)

# Disable optimization and inlining (to facilitate step-by-step debugging)
GCFLAGS = -gcflags "-N -l"

LDFLAGS = -ldflags "-X github.com/snapcore/secboot/internal/testenv.testBinary=enabled"

# List of packages with unit tests (cmd and tools are excluded)
# Packages are referred by their local path (eg: efi/preinstall)
# "secboot" is the top level package and needs special handling as the package name 'secboot' differs from the path '.'.
CHECK_PACKAGES = $(shell go list ./... | sed -e "s;^github.com/snapcore/;;" -e "s;secboot/;;" -e "s;^tools/.*;;" -e "s;^cmd/.*;;")
CHECK_SUBPACKAGES = $(filter-out secboot, $(CHECK_PACKAGES))
CHECK_LOCAL_SUBPACKAGES = $(CHECK_SUBPACKAGES:secboot/%=%)

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

# Test targets:
# - Execution is done in the package directory, as 'testdata' is sought there.
# - Most packages do not need to be tested with a TPM simulator (USE_MSSIM=1),
#   but a few do.
# - Some tests rely on the executable name (eg: 'secboot.test')
secboot.test: FORCE
	go test -cover -c -o secboot.test $(GCFLAGS) . -v $(LDFLAGS) -race -p 1

secboot: secboot.test check-tpm2-simulator
	USE_MSSIM=1 ./$< -test.coverprofile=coverage.out -check.v
	# You may now view the coverage report by executing:
	#     go tool cover -func=$@/coverage.out
	# or: go tool cover -html=$@/coverage.out

$(CHECK_LOCAL_SUBPACKAGES): check-tpm2-simulator FORCE
	go test -cover -c -o ./$@/$(@F).test $(GCFLAGS) ./$@ -v $(LDFLAGS) -race -p 1
	cd $@ && USE_MSSIM=1 ./$(@F).test -test.coverprofile=coverage.out -check.v
	# You may now view the coverage report by executing:
	#     go tool cover -func=$@/coverage.out
	# or: go tool cover -html=$@/coverage.out

fmt:
	go fmt ./...

list-packages:
	@for pkg in $(CHECK_PACKAGES); do echo $$pkg; done
