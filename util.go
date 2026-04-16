package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func getFlagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// writeOutput writes JSON data to a file if --output is specified.
func writeOutput(args []string, v interface{}) {
	outFile := getFlagValue(args, "--output")
	if outFile == "" {
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %s\n", err)
		return
	}
	if err := os.WriteFile(outFile, append(data, '\n'), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %s\n", outFile, err)
	} else {
		fmt.Fprintf(os.Stderr, "Results written to %s\n", outFile)
	}
}
