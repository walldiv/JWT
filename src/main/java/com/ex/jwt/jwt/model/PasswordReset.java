package com.ex.jwt.jwt.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.LocalDateTime;

@Entity
@Table(name = "passwordreset")
public class PasswordReset {
    @Id
    @Column(name = "token", unique = true)
    private String token;
    @Column(name = "email")
    private String email;
    @Column(name = "expirationtime")
    private LocalDateTime expirationtime;

    public PasswordReset() {
    }

    public PasswordReset(String token, String email, LocalDateTime expirationTime) {
        this.token = token;
        this.email = email;
        this.expirationtime = expirationTime;
    }

    @Override
    public String toString() {
        return "PasswordReset{" +
                "token='" + token + '\'' +
                ", email='" + email + '\'' +
                ", expirationTime=" + expirationtime +
                '}';
    }

    public String getToken() {
        return token;
    }
    public void setToken(String token) {
        this.token = token;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public LocalDateTime getExpirationTime() {
        return expirationtime;
    }
    public void setExpirationTime(LocalDateTime expirationTime) {
        this.expirationtime = expirationTime;
    }
}
