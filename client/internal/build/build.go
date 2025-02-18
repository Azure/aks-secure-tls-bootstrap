package build

// version holds the current version string, provided via go ldflags.
var version string

func GetVersion() string {
	return version
}
