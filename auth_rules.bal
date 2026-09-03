// Triggers: ballerina/jwt:1, ballerina/email:1
import ballerina/email;
import ballerina/jwt;

// ballerina/jwt:1 - unsigned JWT
public function issueUnsignedToken() returns error? {
    jwt:IssuerConfig issuerConfig = {
        issuer: "ballerina",
        expTime: 3600,
        signatureConfig: {
            algorithm: jwt:NONE
        }
    };
    string _ = check jwt:issue(issuerConfig);
}

// ballerina/email:1 - TLS hostname verification disabled
public function connectWithoutHostnameCheck() returns error? {
    email:PopClient _ = check new ("pop.example.com", "sender@example.com", "pass123",
        clientConfig = {
            port: 995,
            secureSocket: {
                cert: "path/to/certfile.crt",
                protocol: {
                    name: email:TLS,
                    versions: ["TLSv1.2"]
                },
                verifyHostName: false
            }
        });
}
