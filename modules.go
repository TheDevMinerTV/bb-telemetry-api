package main

var (
	KnownModules = map[string][]string{
		"test": {"1.0.0"},
	}
)

func checkIfValid(module string, version string) bool {
	versions, exists := KnownModules[module]
	if !exists {
		return false
	}

	for _, v := range versions {
		if v == version {
			return true
		}
	}

	return false
}
