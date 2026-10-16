"""Usage: python backup_job.py <database> [pg_dump options...]"""
import os
import subprocess
import sys


def main(args: list[str]) -> int:
    if not args:
        print("usage: backup_job.py <database> [pg_dump options...]", file=sys.stderr)
        return 2
    # Vulnerable: ballerina/os:2 (CWE-15) - the command line decides the environment of every child process.
    os.environ["PGDATABASE"] = args[0]

    # Vulnerable: ballerina/os:1 (CWE-88) and ballerina/os:4 (CWE-426) - command-line input is passed to pg_dump, found through PATH.
    dump = subprocess.run(["pg_dump", *args])
    report_result(args[0], dump.returncode, True)

    # Vulnerable: ballerina/os:1 (CWE-88) and ballerina/os:4 (CWE-426) - the database name from the command line goes straight into tar's arguments.
    archive = subprocess.run(["tar", "-czf", "backup.tgz", args[0]])
    return dump.returncode or archive.returncode


# Vulnerable: ballerina:2 (CWE-561) - verbose is never read.
def report_result(database: str, exit_code: int, verbose: bool) -> None:
    status = "succeeded" if exit_code == 0 else "failed"
    # Vulnerable: ballerina:10 (CWE-1164) - self assignment left over from a refactor.
    status = status
    print(f"Backup of {database} {status} (exit code {exit_code})")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
