package main

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/rmohr/bazeldnf/pkg/api"
	"github.com/rmohr/bazeldnf/pkg/api/bazeldnf"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type Id string

func makeId(pkg *api.Package) Id {
	return Id(pkg.Name)
}

func sortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	keys := maps.Keys(m)
	slices.Sort(keys)
	return keys
}

func toConfig(install, forceIgnored []*api.Package, targets []string, cmdline []string) (*bazeldnf.Config, error) {
	ignored := make(map[Id]bool)
	ignoredNames := make(map[string]bool)
	for _, forceIgnoredPackage := range forceIgnored {
		ignored[makeId(forceIgnoredPackage)] = true
		ignoredNames[forceIgnoredPackage.Name] = true
	}

	allPackages := make(map[Id]*bazeldnf.RPM)
	repositories := make(map[string][]string)
	for _, installPackage := range install {
		repositories[installPackage.Repository.Name] = installPackage.Repository.Mirrors

		deps := make([]string, 0, len(installPackage.Format.Requires.Entries))
		for _, entry := range installPackage.Format.Requires.Entries {
			deps = append(deps, entry.Name)
		}

		slices.Sort(deps)

		integrity, err := installPackage.Checksum.Integrity()
		if err != nil {
			return nil, fmt.Errorf("Unable to read package %s integrity: %w", installPackage.Name, err)
		}

		allPackages[makeId(installPackage)] = &bazeldnf.RPM{
			Id:           string(makeId(installPackage)),
			Name:         installPackage.Name,
			Integrity:    integrity,
			URLs:         []string{installPackage.Location.Href},
			Repository:   installPackage.Repository.Name,
			Dependencies: deps,
		}
	}

	providers := collectProviders(forceIgnored, install)
	packageNames := sortedKeys(allPackages)
	sortedPackages := make([]*bazeldnf.RPM, 0, len(packageNames))
	for _, name := range packageNames {
		pkg := allPackages[name]
		deps, err := collectDependencies(name, pkg.Dependencies, providers, ignored)
		if err != nil {
			return nil, err
		}

		pkg.Dependencies = make([]string, len(deps))
		for i, dep := range deps {
			pkg.Dependencies[i] = string(dep)
		}

		sortedPackages = append(sortedPackages, pkg)
	}

	lockFile := bazeldnf.Config{
		CommandLineArguments: cmdline,
		ForceIgnored:         sortedKeys(ignoredNames),
		RPMs:                 sortedPackages,
		Repositories:         repositories,
		Targets:              targets,
	}

	return &lockFile, nil
}

func collectProviders(pkgSets ...[]*api.Package) map[string]Id {
	providers := map[string]Id{}
	for _, pkgSet := range pkgSets {
		for _, pkg := range pkgSet {
			for _, entry := range pkg.Format.Provides.Entries {
				providers[entry.Name] = makeId(pkg)
			}

			for _, entry := range pkg.Format.Files {
				providers[entry.Text] = makeId(pkg)
			}
		}
	}

	return providers
}

func collectDependencies(pkg Id, requires []string, providers map[string]Id, ignored map[Id]bool) ([]Id, error) {
	depSet := make(map[Id]bool)
	for _, req := range requires {
		logrus.Debugf("Resolving dependency %s", req)
		provider, ok := providers[req]
		if !ok {
			return nil, fmt.Errorf("could not find provider for %s", req)
		}
		logrus.Debugf("Found provider %s for %s", provider, req)
		if ignored[provider] {
			logrus.Debugf("Ignoring provider %s for %s", provider, req)
			continue
		}
		depSet[provider] = true
	}

	deps := sortedKeys(depSet)

	found := map[Id]bool{pkg: true}

	// RPMs may have circular dependencies, even depend on themselves.
	// we need to ignore such dependencies
	nonCyclicDeps := make([]Id, 0, len(deps))
	for _, dep := range deps {
		if found[dep] {
			continue
		}

		nonCyclicDeps = append(nonCyclicDeps, dep)
	}

	return nonCyclicDeps, nil
}
