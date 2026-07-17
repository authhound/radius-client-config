package clientconfig

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The core must stay pure computation: no sockets, no processes, no
// filesystem, no environment. This is the "nothing is transmitted" promise
// made on the website, enforced at test time. crypto/rand and net/netip are
// fine — neither opens a connection.
func TestCoreHasNoImpureImports(t *testing.T) {
	forbidden := map[string]bool{
		"net":      true,
		"net/http": true,
		"net/url":  true,
		"os":       true,
		"os/exec":  true,
		"syscall":  true,
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, file, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if forbidden[path] {
				t.Errorf("%s imports %s — the core must not touch the network, processes, or the OS", file, path)
			}
		}
	}
}
