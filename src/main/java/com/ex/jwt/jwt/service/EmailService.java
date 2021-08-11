package com.ex.jwt.jwt.service;

import com.ex.jwt.jwt.model.PasswordReset;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;

import static com.ex.jwt.jwt.config.EmailConstants.*;

@Component
public class EmailService {
    @Value("${emailsvc.username}")
    private String USERNAME;
    @Value("${emailsvc.password}")
    private String PASSWORD;
    @Value("${finishregister.url}")
    private String FINISHURL;
    @Value("${resetpassword.url}")
    private String RESETURL;

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    public void sendNewPasswordEmail(String firstName, String password, String email) throws MessagingException {
        logger.info("READ USERNAME=> {}     READ PASSWORD => {}", USERNAME, PASSWORD);
        String msg = "Hello " + firstName + " & welcome to the team! \n \n Your new account password is: " + password
                + "\n Please click the below link to finish your account registration. \n \n " + FINISHURL + "?email=" + email
                + "\n \n The Support Team";
        Message message = createEmail(REGISTER_EMAIL_SUBJECT, msg, email);
        Transport.send(message);
    }

    public void sendPasswordResetEmail(String password, PasswordReset passwordReset) throws MessagingException {
        String msg = "Hello user! \n \n You have requested a password reset for your account. \n"
//        + "  Your temporary password is: " + password +"\n \n"
        + "Please click this link to change your password: " + RESETURL + "?token=" + passwordReset.getToken() + "\n \n"
        + "If you did not request a password reset please click here";
        Message message = createEmail(PASSWORD_RESET_EMAIL_SUBJECT, msg, passwordReset.getEmail());
        Transport.send(message);
    }

    private Message createEmail(String subject, String msg, String email) throws MessagingException {
        Message message = new MimeMessage(getEmailSession());
        message.setFrom(new InternetAddress(FROM_EMAIL));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(email));
        message.setSubject(subject);
        message.setText(msg);
        return message;
    }

    private Session getEmailSession() {
        Properties properties = System.getProperties();
        properties.put("mail.smtp.host", GMAIL_SMTP_SERVER);
        properties.put("mail.smtp.port", "465");
        properties.put("mail.smtp.ssl.enable", "true");
        properties.put("mail.smtp.auth", "true");
        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(USERNAME, PASSWORD);
            }
        });
        session.setDebug(true);
        return session;
    }
}
