package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func mkproj(t *testing.T, files map[string]string) string {
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCanonicalOrderIndependent(t *testing.T) {
	a := canonical(map[string]interface{}{"b": float64(1), "a": float64(2)})
	b := canonical(map[string]interface{}{"a": float64(2), "b": float64(1)})
	if string(a) != string(b) {
		t.Fatalf("canonical not order-independent: %s vs %s", a, b)
	}
}

func TestSha256EmptyVector(t *testing.T) {
	if got := sha256hex([]byte("")); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("bad sha256(\"\"): %s", got)
	}
}

func TestPinnedDetection(t *testing.T) {
	dir := mkproj(t, map[string]string{"requirements.txt": "a==1.0\nb>=2\n"})
	comps, err := detectComponents(dir)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]component{}
	for _, c := range comps {
		by[c.Name] = c
	}
	if !by["a"].Pinned {
		t.Error("a should be pinned")
	}
	if by["b"].Pinned {
		t.Error("b should be unpinned")
	}
}

func TestSbomCycloneDX(t *testing.T) {
	dir := mkproj(t, map[string]string{"requirements.txt": "requests==2.31.0\n"})
	bom, err := generateSbom(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bom["bomFormat"] != "CycloneDX" {
		t.Error("not CycloneDX")
	}
}

func TestAttestVerifyRoundtrip(t *testing.T) {
	dir := mkproj(t, map[string]string{"requirements.txt": "a==1.0\n"})
	att, err := attest(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	ok, problems := verify(dir, att, "")
	if !ok {
		t.Fatalf("verify failed: %v", problems)
	}
}

func TestTamperedSignatureFails(t *testing.T) {
	dir := mkproj(t, map[string]string{"requirements.txt": "a==1.0\n"})
	att, _ := attest(dir, "")
	att["signature"].(map[string]interface{})["value"] = hex.EncodeToString(make([]byte, 32))
	if ok, _ := verify(dir, att, ""); ok {
		t.Error("tampered signature should fail")
	}
}

func TestWrongKeyFails(t *testing.T) {
	dir := mkproj(t, map[string]string{"requirements.txt": "a==1.0\n"})
	att, _ := attest(dir, "key-A")
	if ok, _ := verify(dir, att, "key-B"); ok {
		t.Error("wrong key should fail")
	}
}
