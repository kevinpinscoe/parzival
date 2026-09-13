package broker

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// fakeTeaPath is the path to the compiled testdata/faketea fixture binary,
// built once for the whole test binary run. It stands in for the real `tea`
// CLI so this package's tests never depend on a real tea binary, network
// access, or real Gitea credentials.
var fakeTeaPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "parzival-broker-test-fixtures-")
	if err != nil {
		panic("create fixture build dir: " + err.Error())
	}
	fakeTeaPath = filepath.Join(dir, "faketea")

	build := exec.Command("go", "build", "-o", fakeTeaPath, "./testdata/faketea")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("build testdata/faketea fixture: " + err.Error())
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
