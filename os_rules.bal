// Triggers: ballerina/os:1, ballerina/os:2
//
// NOTE: both rules treat command-line arguments as the untrusted source.
// The noncompliant example published for these rules uses HTTP request input
// (`req.getQueryParamValue(...)`), which does NOT trigger them. See RESULTS.md.
import ballerina/os;

public function main(string... args) returns error? {
    // ballerina/os:1 - command-line input used as a system command argument
    os:Process _ = check os:exec({value: "/bin/sh", arguments: args});

    // ballerina/os:2 - command-line input written into an environment variable
    os:Error? _ = os:setEnv("CONFIG_PATH", args[0]);
}
