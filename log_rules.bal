// Triggers: ballerina/log:1
import ballerina/log;

configurable string password = ?;
configurable string user = ?;

// ballerina/log:1 - sensitive configurable values written to the log
public function logCredentials() {
    log:printInfo(password);
    log:printError(string `Error for ${user}: ${password}`);
    log:printWarn("Warning", password = password);
}
