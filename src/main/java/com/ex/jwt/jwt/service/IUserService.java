package com.ex.jwt.jwt.service;

import com.ex.jwt.jwt.exception.exceptions.AlreadyExistsException;
import com.ex.jwt.jwt.exception.exceptions.UsernameNotFoundException;
import com.ex.jwt.jwt.model.PasswordReset;
import com.ex.jwt.jwt.model.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.mail.MessagingException;
import java.io.IOException;

public interface IUserService {
    User register(String firstName, String lastName, String username, String email) throws AlreadyExistsException, MessagingException;

    User findUserByUsername(String username) throws UsernameNotFoundException;

    User findUserByEmail(String email) throws UsernameNotFoundException ;

    void saveUser(User user);

    void verifyUser(String email) throws UsernameNotFoundException;

    boolean resendVerificationEmail(String email);

    //User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, UsernameExistException, EmailExistException, IOException, NotAnImageFileException;

    //User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, UsernameExistException, EmailExistException, IOException, NotAnImageFileException;

    void deleteUser(String username) throws IOException;

    boolean sendPasswordResetEmail(PasswordReset passwordReset);
    void resetPassword(String email, String password)throws UsernameNotFoundException;
    boolean resetPassword(String email, /*String oldPass, */String newPassword, BCryptPasswordEncoder passwordEncoder);
}

