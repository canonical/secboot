package main

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/xerrors"

	"gopkg.in/yaml.v2"
)

var packageDeps = []string{
	"binutils",
	"gcc",
	"make",
	"sbsigntool",
}

type buildEnv struct {
	GoArch        string            `yaml:"go-arch"`
	GoVersion     string            `yaml:"go-version"`
	KernelVersion string            `yaml:"kernel-version"`
	OsRelease     map[string]string `yaml:"os-release"`
	Packages      map[string]string
}

func getPackageDependencies(name string) ([]string, error) {
	cmd := exec.Command("apt-cache", "depends", "--important", "--installed", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`\|?Depends: (.*)`)

	var depends []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		match := re.FindStringSubmatch(strings.TrimSpace(scanner.Text()))
		if match == nil {
			continue
		}
		depends = append(depends, match[1])
	}

	return depends, nil
}

func getCurrentPackageVersion(name string) (string, error) {
	cmd := exec.Command("dpkg-query", "-W", "--showformat", "${Version}", name)
	output, err := cmd.Output()
	return string(output), err
}

func addPackageAndDependenciesRecursively(env *buildEnv, name string) error {
	if _, ok := env.Packages[name]; ok {
		return nil
	}

	version, err := getCurrentPackageVersion(name)
	if err != nil {
		return xerrors.Errorf("cannot determine version: %w", err)
	}
	env.Packages[name] = version

	depends, err := getPackageDependencies(name)
	if err != nil {
		return xerrors.Errorf("cannot determine dependencies: %w", err)
	}
	for _, depend := range depends {
		if err := addPackageAndDependenciesRecursively(env, depend); err != nil {
			return xerrors.Errorf("cannot add package %s and its dependencies: %w", depend, err)
		}
	}

	return nil
}

func addEssentialPackages(env *buildEnv) error {
	cmd := exec.Command("grep-status", "-FEssential", "-sPackage", "-ni", "yes")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		if err := addPackageAndDependenciesRecursively(env, scanner.Text()); err != nil {
			return xerrors.Errorf("cannot add package %s: %w", scanner.Text(), err)
		}
	}

	return scanner.Err()
}

func makeBuildEnvFromCurrent() (*buildEnv, error) {
	env := &buildEnv{
		GoArch:    runtime.GOARCH,
		GoVersion: runtime.Version(),
		OsRelease: make(map[string]string),
		Packages:  make(map[string]string)}

	kernelVersion, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return nil, err
	}
	env.KernelVersion = string(kernelVersion)

	osrel, err := ioutil.ReadFile("/etc/os-release")
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(osrel))
	for scanner.Scan() {
		s := strings.SplitN(scanner.Text(), "=", 2)
		env.OsRelease[s[0]] = s[1]
	}
	if scanner.Err() != nil {
		return nil, xerrors.Errorf("cannot scan /etc/os-release: %w", err)
	}

	if err := addEssentialPackages(env); err != nil {
		return nil, xerrors.Errorf("cannot add essential packages: %w", err)
	}
	for _, dep := range packageDeps {
		if err := addPackageAndDependenciesRecursively(env, dep); err != nil {
			return nil, xerrors.Errorf("cannot add package %s: %w", dep, err)
		}
	}

	return env, nil
}

func recordBuildEnv(dstDir string) error {
	env, err := makeBuildEnvFromCurrent()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(env)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(dstDir, "buildenv.yaml"), data, 0644)
}
