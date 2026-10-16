package demo.backup;

import java.io.IOException;
import java.util.List;

// Usage: java -cp scan-java.jar demo.backup.BackupJob <database> [pg_dump options...]
public final class BackupJob {

    private BackupJob() {
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length == 0) {
            System.err.println("usage: BackupJob <database> [pg_dump options...]");
            System.exit(2);
        }
        // Vulnerable: ballerina/os:1, ballerina/os:4 (CWE-78, CWE-426) - command-line input goes straight to pg_dump, found through PATH.
        ProcessBuilder builder = new ProcessBuilder("pg_dump");
        builder.command().addAll(List.of(args));
        // Vulnerable: ballerina/os:2 (CWE-454) - the command line decides the environment of the child process.
        builder.environment().put("PGDATABASE", args[0]);
        int exitCode = builder.inheritIO().start().waitFor();
        reportResult(args[0], exitCode, true);
    }

    // Vulnerable: ballerina:2 (CWE-561) - verbose is never read.
    private static void reportResult(String database, int exitCode, boolean verbose) {
        String status = exitCode == 0 ? "succeeded" : "failed";
        // Vulnerable: ballerina:10 (CWE-1164) - self assignment left over from a refactor.
        status = status;
        System.out.printf("Backup of %s %s (exit code %d)%n", database, status, exitCode);
    }
}
