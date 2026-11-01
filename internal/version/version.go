package version

import (
	"fmt"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "none"
)

func String() string {
	return fmt.Sprintf("kshield %s (%s) %s/%s", Version, Commit, runtime.GOOS, runtime.GOARCH)
}
