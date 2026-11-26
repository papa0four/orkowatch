// cmd/owatch/network_test.go

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// moduleRoot is the module's directory, from this package's.
const moduleRoot = "../.."

// connectingImports are the packages that exist to open network connections,
// matched as a path or as the start of one.
var connectingImports = []string{"net/http", "crypto/tls", "net/rpc", "net/smtp", "golang.org/x/net", fetchPackage}

// connectingNames are what opens a connection, accepts one, or asks a resolver
// across the network, named by the package that provides them.
var connectingNames = map[string][]string{
	"net": {
		"Dial", "DialIP", "DialTCP", "DialTimeout", "DialUDP", "DialUnix", "Dialer",
		"Listen", "ListenConfig", "ListenIP", "ListenMulticastUDP", "ListenPacket", "ListenTCP", "ListenUDP", "ListenUnix", "ListenUnixgram",
		"LookupAddr", "LookupCNAME", "LookupHost", "LookupIP", "LookupMX", "LookupNS", "LookupPort", "LookupSRV", "LookupTXT",
		"ResolveIPAddr", "ResolveTCPAddr", "ResolveUDPAddr", "ResolveUnixAddr", "Resolver", "DefaultResolver",
	},
	"syscall":                  {"Connect"},
	"golang.org/x/sys/unix":    {"Connect"},
	"golang.org/x/sys/windows": {"Connect", "WSAConnect"},
}

// fetchPackage is the one package of owatch that opens network connections.
const fetchPackage = "github.com/papa0four/orkowatch/internal/dataset/fetch"

// allowedToConnect lists the files that may open a network connection: those
// of the package that fetches datasets, and no other.
var allowedToConnect = []string{"internal/dataset/fetch/fetch.go"}

// allowedToFetch lists the files that may import the package that connects:
// the refresh's, whose steps owatch data refresh and r in the results browser
// run, and no other, so nothing else can reach a connection through it.
var allowedToFetch = []string{"cmd/commands/data_refresh.go"}

// No file of owatch outside the first list above imports a package that
// exists to open network connections, or names a function or type that
// dials, listens, or resolves across the network, and none outside the second
// imports the package that does. This holds for every path through every
// command, since it is a property of the source and not of the runs a test
// happened to make. The modules owatch depends on are not read here.
func TestNoCommandOpensANetworkConnection(t *testing.T) {
	files := 0
	err := filepath.WalkDir(moduleRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if name == "testdata" || (strings.HasPrefix(name, ".") && path != moduleRoot) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		files++
		rel, err := filepath.Rel(moduleRoot, path)
		if err != nil {
			return err
		}
		judge(t, path, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("no Go file was read")
	}
}

// judge fails the test for each way the file at path, named rel within the
// module, could open a connection it is not allowed.
func judge(t *testing.T, path, rel string) {
	t.Helper()
	if slices.Contains(allowedToConnect, rel) {
		return
	}
	for _, found := range connections(t, path) {
		if found == "imports "+fetchPackage && slices.Contains(allowedToFetch, rel) {
			continue
		}
		t.Errorf("%s: %s", rel, found)
	}
}

// connections lists what in the file at path could open a network connection.
func connections(t *testing.T, path string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}

	found, local := importedConnections(t, file)
	return append(found, namedConnections(file, local)...)
}

// importedConnections lists the file's imports of packages that exist to open
// connections, and returns the name each import is known by in the file.
func importedConnections(t *testing.T, file *ast.File) ([]string, map[string]string) {
	t.Helper()
	var found []string
	local := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range connectingImports {
			if importPath == banned || strings.HasPrefix(importPath, banned+"/") {
				found = append(found, "imports "+importPath)
			}
		}
		name := importPath[strings.LastIndex(importPath, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		local[name] = importPath
	}
	return found, local
}

// namedConnections lists where the file names what connects, through the
// imports local names. A port lookup reads the services database, which Go's
// resolver says "is not a DNS operation", so a resolver used for that alone
// is passed; the outer selector is visited before the resolver inside it.
func namedConnections(file *ast.File, local map[string]string) []string {
	var found []string
	portLookups := make(map[*ast.SelectorExpr]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); ok && sel.Sel.Name == portLookup {
			portLookups[inner] = true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || portLookups[sel] {
			return true
		}
		if importPath, imported := local[pkg.Name]; imported && slices.Contains(connectingNames[importPath], sel.Sel.Name) {
			found = append(found, "names "+importPath+"."+sel.Sel.Name)
		}
		return true
	})
	return found
}

// portLookup is the one resolver method that asks nothing of the network.
const portLookup = "LookupPort"
