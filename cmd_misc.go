package main

import (
	"fmt"
	"os"

	"netu/diff"
	"netu/output"
	"netu/service"
)

func cmdDiff(args []string) {
	if len(args) < 2 {
		printCommandHelp("diff")
		os.Exit(1)
	}

	file1 := args[0]
	file2 := args[1]
	jsonOut := hasFlag(args, "--json")

	result, err := diff.CompareFiles(file1, file2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printJSON(result)
		writeOutput(args, result)
		return
	}

	fmt.Printf("Diff: %s vs %s\n\n", file1, file2)
	if len(result.Changes) == 0 {
		fmt.Println("  No differences found.")
		return
	}

	for _, c := range result.Changes {
		switch c.Type {
		case "added":
			fmt.Printf("  %s %s: %s\n", output.Green("+"), c.Key, c.New)
		case "removed":
			fmt.Printf("  %s %s: %s\n", output.Red("-"), c.Key, c.Old)
		case "changed":
			fmt.Printf("  %s %s:\n", output.Yellow("~"), c.Key)
			fmt.Printf("      old: %s\n", c.Old)
			fmt.Printf("      new: %s\n", c.New)
		}
	}
	fmt.Printf("\n%d change(s)\n", len(result.Changes))
}

func cmdServe(args []string) {
	addr := "0.0.0.0:8080"

	for i := 0; i < len(args); i++ {
		if args[i] == "--addr" {
			i++
			addr = args[i]
		}
	}

	if err := service.Start(addr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
