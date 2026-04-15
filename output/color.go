package output

import (
	"fmt"
	"os"
)

var NoColor = false

func init() {
	// Disable color if NO_COLOR env is set or output is not a terminal
	if os.Getenv("NO_COLOR") != "" {
		NoColor = true
		return
	}
	fi, err := os.Stdout.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		NoColor = true
	}
}

const (
	reset  = "\033[0m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
	bold   = "\033[1m"
)

func colorize(color, text string) string {
	if NoColor {
		return text
	}
	return color + text + reset
}

func Green(text string) string  { return colorize(green, text) }
func Red(text string) string    { return colorize(red, text) }
func Yellow(text string) string { return colorize(yellow, text) }
func Cyan(text string) string   { return colorize(cyan, text) }
func Gray(text string) string   { return colorize(gray, text) }
func Bold(text string) string   { return colorize(bold, text) }

// Status returns a colored status indicator
func Status(status string) string {
	switch status {
	case "pass", "open", "UP":
		return Green(status)
	case "fail", "DOWN":
		return Red(status)
	case "warn":
		return Yellow(status)
	default:
		return status
	}
}

// Icon returns a colored icon for check results
func Icon(status string) string {
	switch status {
	case "pass":
		return Green("+")
	case "fail":
		return Red("x")
	case "warn":
		return Yellow("!")
	default:
		return " "
	}
}

// PortState returns colored open/closed text
func PortState(open bool) string {
	if open {
		return Green("open")
	}
	return Red("closed")
}

// Progress prints a simple progress line (overwrites current line)
func Progress(current, total int, label string) {
	if NoColor {
		return
	}
	pct := float64(current) / float64(total) * 100
	fmt.Fprintf(os.Stderr, "\r  %s %.0f%% (%d/%d)", label, pct, current, total)
	if current >= total {
		fmt.Fprintf(os.Stderr, "\r%*s\r", 60, "") // clear line
	}
}
