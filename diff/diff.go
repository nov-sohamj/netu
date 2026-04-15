package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type Change struct {
	Type  string `json:"type"` // "added", "removed", "changed"
	Key   string `json:"key"`
	Old   string `json:"old,omitempty"`
	New   string `json:"new,omitempty"`
}

type Result struct {
	File1   string   `json:"file1"`
	File2   string   `json:"file2"`
	Changes []Change `json:"changes"`
}

// CompareFiles loads two JSON files and compares their top-level keys.
func CompareFiles(file1, file2 string) (Result, error) {
	data1, err := os.ReadFile(file1)
	if err != nil {
		return Result{}, fmt.Errorf("read %s: %w", file1, err)
	}
	data2, err := os.ReadFile(file2)
	if err != nil {
		return Result{}, fmt.Errorf("read %s: %w", file2, err)
	}

	var map1, map2 map[string]interface{}
	if err := json.Unmarshal(data1, &map1); err != nil {
		return Result{}, fmt.Errorf("parse %s: %w", file1, err)
	}
	if err := json.Unmarshal(data2, &map2); err != nil {
		return Result{}, fmt.Errorf("parse %s: %w", file2, err)
	}

	result := Result{File1: file1, File2: file2}

	// Collect all keys
	keys := make(map[string]bool)
	for k := range map1 {
		keys[k] = true
	}
	for k := range map2 {
		keys[k] = true
	}

	var sortedKeys []string
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, k := range sortedKeys {
		v1, in1 := map1[k]
		v2, in2 := map2[k]

		if in1 && !in2 {
			result.Changes = append(result.Changes, Change{
				Type: "removed",
				Key:  k,
				Old:  toJSON(v1),
			})
		} else if !in1 && in2 {
			result.Changes = append(result.Changes, Change{
				Type: "added",
				Key:  k,
				New:  toJSON(v2),
			})
		} else {
			s1 := toJSON(v1)
			s2 := toJSON(v2)
			if s1 != s2 {
				result.Changes = append(result.Changes, Change{
					Type: "changed",
					Key:  k,
					Old:  s1,
					New:  s2,
				})
			}
		}
	}

	return result, nil
}

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
