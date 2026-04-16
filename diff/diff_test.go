package diff

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempJSON(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIdenticalFiles(t *testing.T) {
	f1 := writeTempJSON(t, "a.json", `{"key":"value","num":42}`)
	f2 := writeTempJSON(t, "b.json", `{"key":"value","num":42}`)

	result, err := CompareFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 0 {
		t.Fatalf("expected 0 changes, got %d", len(result.Changes))
	}
}

func TestAddedKey(t *testing.T) {
	f1 := writeTempJSON(t, "a.json", `{"a":1}`)
	f2 := writeTempJSON(t, "b.json", `{"a":1,"b":2}`)

	result, err := CompareFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(result.Changes))
	}
	if result.Changes[0].Type != "added" || result.Changes[0].Key != "b" {
		t.Fatalf("unexpected change: %+v", result.Changes[0])
	}
}

func TestRemovedKey(t *testing.T) {
	f1 := writeTempJSON(t, "a.json", `{"a":1,"b":2}`)
	f2 := writeTempJSON(t, "b.json", `{"a":1}`)

	result, err := CompareFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(result.Changes))
	}
	if result.Changes[0].Type != "removed" || result.Changes[0].Key != "b" {
		t.Fatalf("unexpected change: %+v", result.Changes[0])
	}
}

func TestChangedValue(t *testing.T) {
	f1 := writeTempJSON(t, "a.json", `{"status":"ok"}`)
	f2 := writeTempJSON(t, "b.json", `{"status":"error"}`)

	result, err := CompareFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(result.Changes))
	}
	c := result.Changes[0]
	if c.Type != "changed" || c.Key != "status" {
		t.Fatalf("unexpected change: %+v", c)
	}
	if c.Old != `"ok"` || c.New != `"error"` {
		t.Fatalf("unexpected old/new: %q / %q", c.Old, c.New)
	}
}

func TestMultipleChanges(t *testing.T) {
	f1 := writeTempJSON(t, "a.json", `{"a":1,"b":2,"c":3}`)
	f2 := writeTempJSON(t, "b.json", `{"a":1,"b":99,"d":4}`)

	result, err := CompareFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}
	// b changed, c removed, d added = 3 changes
	if len(result.Changes) != 3 {
		t.Fatalf("expected 3 changes, got %d", len(result.Changes))
	}
}

func TestInvalidJSON(t *testing.T) {
	f1 := writeTempJSON(t, "a.json", `not json`)
	f2 := writeTempJSON(t, "b.json", `{"a":1}`)

	_, err := CompareFiles(f1, f2)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMissingFile(t *testing.T) {
	f2 := writeTempJSON(t, "b.json", `{"a":1}`)
	_, err := CompareFiles("/nonexistent/file.json", f2)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestEmptyObjects(t *testing.T) {
	f1 := writeTempJSON(t, "a.json", `{}`)
	f2 := writeTempJSON(t, "b.json", `{}`)

	result, err := CompareFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 0 {
		t.Fatalf("expected 0 changes, got %d", len(result.Changes))
	}
}
