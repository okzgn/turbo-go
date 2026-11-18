package main

// Review of 6046dbe (R6), O-7: the command of a preprocessor asks for the working directory only when its value
// names it. Before, each request to a CGI asked the system for it, used or not.

import (
	"strings"
	"testing"
)

func TestR6_O7_PreprocessorCommandWithoutTheWorkingDirectory(t *testing.T) {
	for value, expected := range map[string]string{
		"/usr/bin/php-cgi":                              "/usr/bin/php-cgi",
		"cgi>C:/php/php-cgi.exe":                        "C:/php/php-cgi.exe",
		"CGI>/opt/{OTHER}/bin":                          "/opt/{OTHER}/bin",
		"{TURBO_CURRENT_DIR}/php/php-cgi":               currentDir() + "/php/php-cgi",
		"cgi>{TURBO_CURRENT_DIR}/a/{TURBO_CURRENT_DIR}": currentDir() + "/a/{TURBO_CURRENT_DIR}", // Only the first, as before
	} {
		if executable, problem := preprocessorCommand(value); executable != expected || problem != "" {
			t.Errorf("preprocessorCommand(%q) = %q, %q; expected %q", value, executable, problem, expected)
		}
	}
	for _, value := range []string{"", "dx>/usr/bin/php", strings.Repeat("a", 129), invalidPreprocessorMark + "x"} {
		if executable, problem := preprocessorCommand(value); executable != "" || problem == "" {
			t.Errorf("preprocessorCommand(%q) = %q, %q; expected a problem", value, executable, problem)
		}
	}
	if raceEnabled {
		return // The race detector allocates on its own
	}
	if allocations := testing.AllocsPerRun(100, func() { preprocessorCommand("cgi>/usr/bin/php-cgi") }); allocations != 0 {
		t.Errorf("a command without {TURBO_CURRENT_DIR}: %.0f allocations; expected none (the working directory isn't asked for)", allocations)
	}
}
