// Triggers: ballerina/file:1, ballerina/file:2, ballerina/io:1
import ballerina/file;
import ballerina/http;
import ballerina/io;
import ballerina/os;

// ballerina/file:1 - operating on a publicly writable directory
public function writeToTempDir() returns error? {
    string tempFolderPath = os:getEnv("TMP");
    check file:create(tempFolderPath + "/" + "myfile.txt");
    _ = check file:createTemp("suffix", "prefix");
    _ = check file:createTempDir((), "prefix");
}

string targetDirectory = "./path/to/target/directory/";

// ballerina/file:2 - user input concatenated into a file path (path injection)
service /files on new http:Listener(8085) {
    resource function get deleteFile(string fileName) returns string|error {
        check file:remove(targetDirectory + fileName);
        return "deleted";
    }
}

// ballerina/io:1 - user input concatenated into a path passed to an io: read
service /fileService on new http:Listener(8086) {
    resource function get file(string fileName) returns string|error {
        string filePath = "./resources/" + fileName;
        string content = check io:fileReadString(filePath);
        return content;
    }
}
