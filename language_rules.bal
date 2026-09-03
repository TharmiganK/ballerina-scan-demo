// Triggers a sample of the language rules, so the report contains more than one rule kind
import ballerina/io;

// ballerina:1 - checkpanic terminates the program instead of handling the error
public function readOrPanic(string path) returns string {
    return checkpanic io:fileReadString(path);
}

// ballerina:2 - unused function parameter
public function greet(string name, int unusedCount) returns string {
    return "Hello " + name;
}

// ballerina:10 - self assignment
public function selfAssign() {
    int count = 5;
    count = count;
    io:println(count);
}
