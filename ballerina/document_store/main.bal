import ballerina/file;
import ballerina/http;
import ballerina/io;
import ballerina/os;

configurable string storageRoot = "./documents/";

service /documents on new http:Listener(9092) {

    resource function put [string name](@http:Payload byte[] content) returns http:Created|error {
        // Vulnerable: ballerina/file:1 - uploads are staged in the world-writable system temp directory.
        string stagingDir = os:getEnv("TMP");
        string stagedPath = stagingDir + "/upload.bin";
        check file:create(stagedPath);
        check io:fileWriteBytes(stagedPath, content);
        check file:copy(stagedPath, storageRoot + name, file:REPLACE_EXISTING);
        return http:CREATED;
    }

    resource function get [string name]() returns byte[]|error {
        // Vulnerable: ballerina/io:1 - the document name is joined into the path unchecked.
        byte[] content = check io:fileReadBytes(storageRoot + name);
        return content;
    }

    resource function delete [string name]() returns http:NoContent|error {
        // Vulnerable: ballerina/file:2 - "../" in the name deletes files outside the store.
        check file:remove(storageRoot + name);
        return http:NO_CONTENT;
    }
}
