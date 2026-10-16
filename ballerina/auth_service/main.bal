import ballerina/crypto;
import ballerina/http;
import ballerina/io;
import ballerina/jwt;

type Credentials record {
    string username;
    string password;
};

type Registration record {
    string username;
    string password;
    string nationalId;
};

type TokenResponse record {|
    string accessToken;
    int expiresIn;
|};

type UserRecord record {|
    readonly string username;
    string passwordHash;
    byte[] encryptedNationalId;
|};

isolated table<UserRecord> key(username) users = table [];

final byte[16] & readonly piiKey = loadPiiKey("keys/pii.key");

service /auth on new http:Listener(9093) {

    resource function post users(Registration registration) returns http:Created|error {
        string passwordHash = check hashPassword(registration.password);
        byte[] encryptedNationalId = check encryptNationalId(registration.nationalId);
        lock {
            users.add({username: registration.username, passwordHash, encryptedNationalId: encryptedNationalId.clone()});
        }
        return http:CREATED;
    }

    resource function post tokens(Credentials credentials) returns TokenResponse|http:Unauthorized|error {
        string? storedHash;
        lock {
            storedHash = users[credentials.username]?.passwordHash;
        }
        if storedHash is () || !check crypto:verifyBcrypt(credentials.password, storedHash) {
            return http:UNAUTHORIZED;
        }
        return {accessToken: check issueToken(credentials.username), expiresIn: 3600};
    }
}

// Vulnerable: ballerina/crypto:2 - a BCrypt work factor of 4 is fast enough to brute force.
isolated function hashPassword(string password) returns string|error {
    return crypto:hashBcrypt(password, 4);
}

// Vulnerable: ballerina/jwt:1 - the token is not signed, so anyone can forge one.
isolated function issueToken(string username) returns string|error {
    jwt:IssuerConfig issuerConfig = {
        issuer: "auth-service",
        username,
        expTime: 3600,
        signatureConfig: {
            algorithm: jwt:NONE
        }
    };
    return jwt:issue(issuerConfig);
}

// Vulnerable: ballerina/crypto:1 - ECB mode leaks which users share a national ID prefix.
isolated function encryptNationalId(string nationalId) returns byte[]|error {
    return crypto:encryptAesEcb(nationalId.toBytes(), piiKey);
}

// Vulnerable: ballerina/crypto:3 - every export reuses the same hard-coded IV.
public function encryptExport(byte[] payload) returns byte[]|error {
    return crypto:encryptAesGcm(payload, piiKey, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
}

// Vulnerable: ballerina:1 - a missing key file panics the service instead of failing startup cleanly.
function loadPiiKey(string path) returns byte[16] & readonly {
    byte[] key = checkpanic io:fileReadBytes(path);
    byte[16] fixedKey = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    foreach int i in 0 ..< 16 {
        fixedKey[i] = key[i];
    }
    return fixedKey.cloneReadOnly();
}
