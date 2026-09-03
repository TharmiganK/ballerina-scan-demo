// Triggers: ballerina/http:1, ballerina/http:2, ballerina/http:3, ballerina/http:4
import ballerina/http;

// ballerina/http:1 - default accessor responds to any HTTP method, including unsafe ones
service /legacy on new http:Listener(8081) {
    resource function default .() returns string? {
        return;
    }
}

// ballerina/http:2 - CORS allows every origin
@http:ServiceConfig {
    cors: {
        allowOrigins: ["*"]
    }
}
service /open on new http:Listener(8082) {
    resource function get greet() returns string? {
        return;
    }
}

// ballerina/http:3 - user-controlled path segment used in a server-side request (SSRF)
service /proxy on new http:Listener(8083) {
    resource function get fetch(string path) returns string|error {
        http:Client backend = check new ("http://internal.example.com");
        json response = check backend->/api/[path];
        return response.toJsonString();
    }
}

// ballerina/http:4 - user-controlled value placed in the Location header (open redirect)
service /redirect on new http:Listener(8084) {
    resource function get go/[string location]() returns http:TemporaryRedirect {
        return {
            headers: {
                "Location": location
            }
        };
    }
}
