// Command backup dumps a PostgreSQL database.
//
// Usage: backup <database> [pg_dump options...]
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: backup <database> [pg_dump options...]")
	}
	// Vulnerable: ballerina/os:2 (CWE-454) - the command line decides the environment of every child process.
	if err := os.Setenv("PGDATABASE", args[0]); err != nil {
		return err
	}

	// Vulnerable: ballerina/os:1 (CWE-78) and ballerina/os:4 (CWE-426) - command-line input is passed to pg_dump, resolved through PATH.
	cmd := exec.Command("pg_dump", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	exitCode := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		return err
	}
	reportResult(args[0], exitCode, true)

	// Vulnerable: ballerina/os:1 (CWE-78) and ballerina/os:4 (CWE-426) - the database name from the command line goes straight into tar's arguments.
	return exec.Command("tar", "-czf", "backup.tgz", args[0]).Run()
}

// Vulnerable: ballerina:2 (CWE-561) - verbose is never read.
func reportResult(database string, exitCode int, verbose bool) {
	status := "failed"
	if exitCode == 0 {
		status = "succeeded"
	}
	// Vulnerable: ballerina:10 (CWE-1164) - self assignment left over from a refactor.
	status = status
	fmt.Printf("Backup of %s %s (exit code %d)\n", database, status, exitCode)
}
