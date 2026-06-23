// attestport (Go port) — air-gap supply-chain SBOM + provenance, mirroring the
// primary Python CLI's `sbom`, `attest`, and `verify` commands. Standard library
// only (crypto, encoding/json, os) — no modules, no network.
//
//	go run . sbom   <dir>
//	go run . attest <artifact> [--key K]
//	go run . verify <artifact> <attestation.json> [--key K]
//	go run . --version
//
// Uses the same canonical-JSON + HMAC-SHA256 scheme as the Python and Node
// implementations, so an attestation made by one verifies under the others on a
// shared key.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	toolName    = "attestport"
	toolVersion = "0.1.0"
	cyclonedx   = "1.5"
	intoto      = "https://in-toto.io/Statement/v1"
	slsa        = "https://slsa.dev/provenance/v1"
)

var (
	skipDirs   = map[string]bool{".git": true, "node_modules": true, "__pycache__": true, ".venv": true, "venv": true, "dist": true, "build": true, ".pytest_cache": true, "target": true, ".idea": true, ".vscode": true}
	unpinnedRe = regexp.MustCompile(`[<>~^*]|\bx\b|,| - |\|\|`)
	reqRe      = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*(.*)$`)
)

type component struct {
	Name, Version, Ecosystem, Purl string
	Pinned                         bool
}

func canonical(v interface{}) []byte {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.Write(canonical(t[k]))
		}
		b.WriteByte('}')
		return []byte(b.String())
	case []interface{}:
		var b strings.Builder
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(canonical(e))
		}
		b.WriteByte(']')
		return []byte(b.String())
	default:
		out, _ := json.Marshal(v)
		return out
	}
}

func sha256hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func purl(eco, name, version string) string {
	safe := strings.ReplaceAll(name, "@", "%40")
	if version != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", eco, safe, version)
	}
	return fmt.Sprintf("pkg:%s/%s", eco, safe)
}

func parseRequirements(text string) []component {
	var out []component
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		line = strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		m := reqRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, spec := m[1], strings.TrimSpace(m[3])
		pinned := strings.HasPrefix(spec, "==") && !unpinnedRe.MatchString(spec[2:])
		version := spec
		if strings.HasPrefix(spec, "==") {
			version = strings.TrimSpace(spec[2:])
		} else {
			version = strings.TrimLeft(spec, "=<>~!^ ")
		}
		pv := ""
		if pinned {
			pv = version
		}
		out = append(out, component{name, version, "pypi", purl("pypi", name, pv), pinned})
	}
	return out
}

func detectComponents(dir string) ([]component, error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", dir)
	}
	var comps []component
	if data, err := os.ReadFile(filepath.Join(dir, "requirements.txt")); err == nil {
		comps = append(comps, parseRequirements(string(data))...)
	}
	seen := map[string]bool{}
	var out []component
	for _, c := range comps {
		k := c.Ecosystem + "|" + c.Name + "|" + c.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Ecosystem+strings.ToLower(out[i].Name)+out[i].Version <
			out[j].Ecosystem+strings.ToLower(out[j].Name)+out[j].Version
	})
	return out, nil
}

type fileEntry struct{ Path, Sha256 string }

func hashTree(dir string) []fileEntry {
	var files []fileEntry
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		files = append(files, fileEntry{filepath.ToSlash(rel), sha256hex(data)})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

func merkle(files []fileEntry) string {
	arr := make([]interface{}, len(files))
	for i, f := range files {
		arr[i] = []interface{}{f.Path, f.Sha256}
	}
	return sha256hex(canonical(arr))
}

func generateSbom(dir string) (map[string]interface{}, error) {
	comps, err := detectComponents(dir)
	if err != nil {
		return nil, err
	}
	files := hashTree(dir)
	root := filepath.Base(dir)
	digest := merkle(files)
	u := sha256hex([]byte(root + "|" + digest))
	serial := fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", u[0:8], u[8:12], u[12:16], u[16:20], u[20:32])
	var cdx []interface{}
	for _, c := range comps {
		pinned := "false"
		if c.Pinned {
			pinned = "true"
		}
		cdx = append(cdx, map[string]interface{}{
			"type": "library", "name": c.Name, "version": c.Version,
			"bom-ref": c.Purl, "purl": c.Purl,
			"properties": []interface{}{
				map[string]interface{}{"name": "attestport:ecosystem", "value": c.Ecosystem},
				map[string]interface{}{"name": "attestport:pinned", "value": pinned}},
		})
	}
	return map[string]interface{}{
		"bomFormat": "CycloneDX", "specVersion": cyclonedx,
		"serialNumber": serial, "version": float64(1),
		"metadata": map[string]interface{}{
			"tools":     []interface{}{map[string]interface{}{"vendor": "Cognis Digital", "name": toolName, "version": toolVersion}},
			"component": map[string]interface{}{"type": "application", "name": root, "bom-ref": "root:" + root}},
		"components": cdx,
	}, nil
}

func resolveKey(key string) []byte {
	if key != "" {
		return []byte(key)
	}
	if env := os.Getenv("ATTESTPORT_KEY"); env != "" {
		return []byte(env)
	}
	return []byte("attestport-insecure-demo-key")
}

func subjectDigest(artifact string) string {
	info, _ := os.Stat(artifact)
	if info != nil && info.IsDir() {
		return merkle(hashTree(artifact))
	}
	data, _ := os.ReadFile(artifact)
	return sha256hex(data)
}

func attest(artifact, key string) (map[string]interface{}, error) {
	if _, err := os.Stat(artifact); err != nil {
		return nil, fmt.Errorf("artifact not found: %s", artifact)
	}
	statement := map[string]interface{}{
		"_type": intoto, "predicateType": slsa,
		"subject": []interface{}{map[string]interface{}{
			"name": filepath.Base(artifact), "digest": map[string]interface{}{"sha256": subjectDigest(artifact)}}},
		"predicate": map[string]interface{}{
			"buildType": "https://cognis.digital/attestport/buildtype/v1",
			"builder":   map[string]interface{}{"id": "attestport:local"},
			"invocation": map[string]interface{}{"configSource": map[string]interface{}{}},
			"materials":  []interface{}{}},
	}
	payload := canonical(statement)
	mac := hmac.New(sha256.New, resolveKey(key))
	mac.Write(payload)
	sig := hex.EncodeToString(mac.Sum(nil))
	statement["signature"] = map[string]interface{}{
		"algorithm": "hmac-sha256", "value": sig, "payloadSha256": sha256hex(payload)}
	return statement, nil
}

func verify(artifact string, att map[string]interface{}, key string) (bool, []string) {
	var problems []string
	sig, ok := att["signature"].(map[string]interface{})
	if !ok || sig["value"] == nil {
		return false, []string{"no signature"}
	}
	statement := map[string]interface{}{}
	for k, v := range att {
		if k != "signature" {
			statement[k] = v
		}
	}
	payload := canonical(statement)
	mac := hmac.New(sha256.New, resolveKey(key))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(fmt.Sprint(sig["value"]))) != 1 {
		problems = append(problems, "signature mismatch")
	}
	if _, err := os.Stat(artifact); err != nil {
		problems = append(problems, "artifact not found: "+artifact)
	} else {
		actual := subjectDigest(artifact)
		subs, _ := att["subject"].([]interface{})
		claimed := ""
		if len(subs) > 0 {
			if s, ok := subs[0].(map[string]interface{}); ok {
				if d, ok := s["digest"].(map[string]interface{}); ok {
					claimed = fmt.Sprint(d["sha256"])
				}
			}
		}
		if claimed != actual {
			problems = append(problems, "subject digest mismatch")
		}
	}
	return len(problems) == 0, problems
}

func flagVal(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func positional(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: attestport {sbom|attest|verify|--version}")
		return 2
	}
	cmd := args[0]
	rest := args[1:]
	pos := positional(rest)
	switch cmd {
	case "--version", "-v":
		fmt.Printf("%s %s\n", toolName, toolVersion)
		return 0
	case "sbom":
		bom, err := generateSbom(pos[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		out, _ := json.MarshalIndent(bom, "", "  ")
		fmt.Println(string(out))
		return 0
	case "attest":
		att, err := attest(pos[0], flagVal(rest, "--key"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		out, _ := json.MarshalIndent(att, "", "  ")
		fmt.Println(string(out))
		return 0
	case "verify":
		data, err := os.ReadFile(pos[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		var att map[string]interface{}
		json.Unmarshal(data, &att)
		ok, problems := verify(pos[0], att, flagVal(rest, "--key"))
		if ok {
			fmt.Println("VERIFY: PASS")
			return 0
		}
		fmt.Println("VERIFY: FAIL")
		for _, p := range problems {
			fmt.Println("  - " + p)
		}
		return 1
	}
	fmt.Fprintln(os.Stderr, "unknown command:", cmd)
	return 2
}

func main() { os.Exit(run(os.Args[1:])) }
