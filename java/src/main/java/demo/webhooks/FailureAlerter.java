package demo.webhooks;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class FailureAlerter {

    private final String smtpHost;
    private final String smtpUser;
    private final String smtpPassword;
    private final String alertRecipient;

    public FailureAlerter(@Value("${smtp.host}") String smtpHost,
                          @Value("${smtp.user}") String smtpUser,
                          @Value("${smtp.password}") String smtpPassword,
                          @Value("${alert.recipient}") String alertRecipient) {
        this.smtpHost = smtpHost;
        this.smtpUser = smtpUser;
        this.smtpPassword = smtpPassword;
        this.alertRecipient = alertRecipient;
    }

    public void sendFailureAlert(String target, String reason) throws MessagingException {
        Properties props = new Properties();
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", "465");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.ssl.enable", "true");
        // Vulnerable: ballerina/email:1 (CWE-297) - the SMTP server certificate is not matched against its host name.
        props.put("mail.smtp.ssl.checkserveridentity", "false");
        Session session = Session.getInstance(props);

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(smtpUser));
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(alertRecipient));
        message.setSubject("Webhook delivery to " + target + " failed");
        message.setText(reason);
        Transport.send(message, smtpUser, smtpPassword);
    }
}
