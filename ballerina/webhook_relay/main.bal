import ballerina/email;
import ballerina/http;
import ballerina/log;

configurable string subscriberBaseUrl = "http://subscribers.internal.example.com";
configurable string relayApiKey = ?;
configurable string smtpHost = ?;
configurable string smtpUser = ?;
configurable string smtpPassword = ?;
configurable string alertRecipient = "ops@example.com";

type WebhookEvent record {
    string 'type;
    json data;
};

service /webhooks on new http:Listener(9091) {

    // Vulnerable: ballerina/http:3 - the caller picks the internal path the relay calls (SSRF).
    resource function post [string target](WebhookEvent event) returns json|error {
        // Vulnerable: ballerina/log:1 - the API key is written to the log.
        log:printDebug(string `Relaying ${event.'type} to ${target} with key ${relayApiKey}`);
        http:Client subscriber = check new (subscriberBaseUrl);
        json ack = check subscriber->/hooks/[target];
        return ack;
    }
}

function sendFailureAlert(string target, string reason) returns error? {
    // Vulnerable: ballerina/email:1 - the SMTP server certificate is not matched against its host name.
    email:SmtpClient smtpClient = check new (smtpHost, smtpUser, smtpPassword,
        clientConfig = {
            port: 465,
            security: email:SSL,
            secureSocket: {
                cert: "certs/smtp.crt",
                verifyHostName: false
            }
        });
    check smtpClient->sendMessage({
        to: alertRecipient,
        subject: string `Webhook delivery to ${target} failed`,
        body: reason
    });
}
