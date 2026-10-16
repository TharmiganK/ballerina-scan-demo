import ballerina/io;
import ballerina/os;

// Usage: bal run backup_job -- <database> [pg_dump options...]
public function main(string... args) returns error? {
    if args.length() == 0 {
        return error("usage: backup_job <database> [pg_dump options...]");
    }
    // Vulnerable: ballerina/os:2 - the command line decides the environment of every child process.
    check os:setEnv("PGDATABASE", args[0]);

    // Vulnerable: ballerina/os:1 - command-line input is passed straight to pg_dump.
    os:Process dump = check os:exec({value: "pg_dump", arguments: args});
    int exitCode = check dump.waitForExit();
    reportResult(args[0], exitCode, true);
}

// Vulnerable: ballerina:2 - verbose is never read.
function reportResult(string database, int exitCode, boolean verbose) {
    string status = exitCode == 0 ? "succeeded" : "failed";
    // Vulnerable: ballerina:10 - self assignment left over from a refactor.
    status = status;
    io:println(string `Backup of ${database} ${status} (exit code ${exitCode})`);
}
