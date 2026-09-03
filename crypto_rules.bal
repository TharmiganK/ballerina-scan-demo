// Triggers: ballerina/crypto:1, ballerina/crypto:2, ballerina/crypto:3
import ballerina/crypto;

// ballerina/crypto:1 - AES-ECB is an insecure cipher mode
public function encryptWithEcb(string plaintext) returns error? {
    byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    byte[] _ = check crypto:encryptAesEcb(plaintext.toBytes(), key);
}

// ballerina/crypto:2 - BCrypt work factor below the recommended minimum of 10
public function hashPasswordWeakly(string password) returns error? {
    string _ = check crypto:hashBcrypt(password, 4);
}

// ballerina/crypto:3 - hardcoded initialization vector reused across encryptions
public function encryptWithFixedIv(string data) returns error? {
    byte[16] key = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    byte[] _ = check crypto:encryptAesGcm(data.toBytes(), key,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
}
