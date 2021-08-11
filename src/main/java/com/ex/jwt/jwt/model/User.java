package com.ex.jwt.jwt.model;


import javax.persistence.*;
import java.time.LocalDate;
import java.util.Set;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private int userid;
    @Column(name = "firstname")
    private String firstname;
    @Column(name = "lastname")
    private String lastname;
    @Column(name = "dateofbirth")
    private LocalDate dateofbirth;
    @Column(name = "username", unique = true)
    private String username;
    @Column(name = "email", unique = true)
    private String email;
    @Column(name = "password", length = 60)
    private String password;
    @Column(name = "role")
    private String role;
    @Column(name = "authorities")
    private String authorities;
    @Column(name = "joindate")
    private LocalDate joindate;
    @Column(name = "lastlogindate")
    private LocalDate lastlogindate;
    @Column(name = "islockedout")
    private boolean islockedout;
    @Column(name = "isaccountverified")
    private boolean isaccountverified;


    public User() {
    }

    public User(int userid, String firstname, String lastname, LocalDate dateofbirth, String username, String email, String password, String role, String authorities, LocalDate joindate, LocalDate lastlogindate, boolean islockedout, boolean isaccountverified) {
        this.userid = userid;
        this.firstname = firstname;
        this.lastname = lastname;
        this.dateofbirth = dateofbirth;
        this.username = username;
        this.email = email;
        this.password = password;
        this.role = role;
        this.authorities = authorities;
        this.joindate = joindate;
        this.lastlogindate = lastlogindate;
        this.islockedout = islockedout;
        this.isaccountverified = isaccountverified;
    }

    //FOR REGISTRATION
    public User(String firstName, String lastName, String username, String email){
        this.firstname = firstName;
        this.lastname = lastName;
        this.username = username;
        this.email = email;
    }

    //FOR LOGIN
    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public String toString() {
        return "User{" +
                "userid=" + userid +
                ", firstname='" + firstname + '\'' +
                ", lastname='" + lastname + '\'' +
                ", dateofbirth=" + dateofbirth +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", role='" + role + '\'' +
                ", authorities='" + authorities + '\'' +
                ", joindate=" + joindate +
                ", lastlogindate=" + lastlogindate +
                ", islockedout=" + islockedout +
                ", isaccountverified=" + isaccountverified +
                '}';
    }

    public int getUserid() {
        return userid;
    }
    public void setUserid(int userid) {
        this.userid = userid;
    }
    public String getFirstname() {
        return firstname;
    }
    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }
    public String getLastname() {
        return lastname;
    }
    public void setLastname(String lastname) {
        this.lastname = lastname;
    }
    public LocalDate getDateofbirth() {
        return dateofbirth;
    }
    public void setDateofbirth(LocalDate dateofbirth) {
        this.dateofbirth = dateofbirth;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public String getRole() {
        return role;
    }
    public void setRole(String role) {
        this.role = role;
    }
    public String getAuthorities() {
        return authorities;
    }
    public void setAuthorities(String authorities) {
        this.authorities = authorities;
    }
    public LocalDate getJoindate() {
        return joindate;
    }
    public void setJoindate(LocalDate joindate) {
        this.joindate = joindate;
    }
    public LocalDate getLastlogindate() {
        return lastlogindate;
    }
    public void setLastlogindate(LocalDate lastlogindate) {
        this.lastlogindate = lastlogindate;
    }
    public boolean isIslockedout() {
        return islockedout;
    }
    public void setIslockedout(boolean islockedout) {
        this.islockedout = islockedout;
    }
    public boolean isIsaccountverified() {
        return isaccountverified;
    }
    public void setIsaccountverified(boolean isaccountverified) {
        this.isaccountverified = isaccountverified;
    }
}
