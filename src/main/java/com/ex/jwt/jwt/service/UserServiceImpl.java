package com.ex.jwt.jwt.service;

import com.ex.jwt.jwt.exception.exceptions.AlreadyExistsException;
import com.ex.jwt.jwt.exception.exceptions.UsernameNotFoundException;
import com.ex.jwt.jwt.model.PasswordReset;
import com.ex.jwt.jwt.model.User;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.transaction.Transactional;
import java.io.IOException;
import java.time.LocalDate;

import static com.ex.jwt.jwt.config.RolesEnum.ROLE_USER;


@Service
@Transactional
@Qualifier("userDetailsService")
public class UserServiceImpl implements IUserService, UserDetailsService {
    private Logger logger = LoggerFactory.getLogger(getClass());
    private BCryptPasswordEncoder passwordEncoder;
    private UserRepository userRepository;
    private EmailService emailService;
    private PasswordResetRepository passwordRepo;

    private static final String ALREADY_EXISTS = "The username or email already exists - please choose another";

    @Autowired
    public UserServiceImpl(BCryptPasswordEncoder passwordEncoder, UserRepository userRepository,
                           EmailService emailService, PasswordResetRepository passwordRepo) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.passwordRepo = passwordRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return null;
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    @Override
    public User register(String firstName, String lastName, String username, String email) throws AlreadyExistsException, MessagingException {
        User tmpName = userRepository.findByUsername(username);
        User tmpEmail = userRepository.findByEmail(email);
        if((tmpName != null) || (tmpEmail != null)){
            logger.error("ALREADY EXISTS - THROWING EXCEPTION");
            throw new AlreadyExistsException(ALREADY_EXISTS);
        }
        else{
            User tmp = new User(firstName, lastName, username, email);
            String password = generatePassword();
            tmp.setPassword(encodePassword(password));
            tmp.setRole(ROLE_USER.name());
            tmp.setAuthorities(ROLE_USER.getAuthorities());
            tmp.setJoindate(LocalDate.now());
            logger.info("NEW USER PASSWORD => {}", password);
            logger.info("AUTHORITIES => {}", tmp.getAuthorities());
            User saved = null;
            try{
               saved = userRepository.save(tmp);
               if(saved != null)
                   emailService.sendNewPasswordEmail(firstName, password, email);
            } catch (Exception e) {
                logger.error(e.toString());
            }
            return saved;
        }
    }


    @Override
    public User findUserByUsername(String username) throws UsernameNotFoundException {
        User tmp = userRepository.findByUsername(username);
        if(tmp == null)
            throw new UsernameNotFoundException("blah");
        else
            return tmp;
    }

    @Override
    public User findUserByEmail(String email) throws UsernameNotFoundException {
        try{
            User tmp = this.userRepository.findByEmail(email);
            if(tmp == null)
                throw new UsernameNotFoundException("blah");
            return tmp;
        } catch (UsernameNotFoundException e) {
            return null;
        }
    }

    @Override
    public void deleteUser(String username) throws IOException {

    }

    @Override
    public void saveUser(User user){
        this.userRepository.save(user);
    }

    @Override
    public void verifyUser(String email) throws UsernameNotFoundException{
        try{
            User tmp = this.userRepository.findByEmail(email);
            if (tmp == null)
                throw new UsernameNotFoundException("bleh");
            tmp.setIsaccountverified(true);
            this.userRepository.save(tmp);
        } catch (Exception e) {
            throw new UsernameNotFoundException("bleh");
        }
    }

    @Override
    public boolean resendVerificationEmail(String email) {
        try{
            String password = generatePassword();
            resetPassword(email, password);
            User tmp = this.userRepository.findByEmail(email);
            this.emailService.sendNewPasswordEmail(tmp.getFirstname(), password, tmp.getEmail());
        } catch (UsernameNotFoundException | MessagingException e) {
//            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean sendPasswordResetEmail(PasswordReset passwordReset) {
        try{
            try{
                this.passwordRepo.save(passwordReset);
            } catch (Exception e) {
                return false;
            }
            String password = generatePassword();
            this.emailService.sendPasswordResetEmail(password, passwordReset);
            //REMOVED PER REQUEST - Lydon/An
//            resetPassword(passwordReset.getEmail(), password);
        } catch (UsernameNotFoundException | MessagingException e) {
            return false;
        }
        return true;
    }

    @Override
    public void resetPassword(String email, String password) throws UsernameNotFoundException{
        try{
            User tmp = this.userRepository.findByEmail(email);
            if(tmp == null)
                throw new UsernameNotFoundException("blah");
            tmp.setPassword(encodePassword(password));
            tmp.setIslockedout(false);
            this.userRepository.save(tmp);
        } catch (Exception e) {
            logger.error("USERSERVICEIMPL::resetPassword() => ERROR: {}", e.toString());
        }
    }

    @Override
    public boolean resetPassword(String email,/* String oldPass,*/ String newPassword, BCryptPasswordEncoder passwordEncoder){
        try{
            User tmp = this.userRepository.findByEmail(email);
//            logger.info("PASSWORD MATCHING: => {}", passwordEncoder.matches(oldPass, tmp.getPassword()));
            if(tmp==null /*|| !passwordEncoder.matches(oldPass, tmp.getPassword())*/)
                throw new UsernameNotFoundException("blah");
            tmp.setPassword(encodePassword(newPassword));
            this.userRepository.save(tmp);
            return true;
        } catch (UsernameNotFoundException e) {
            logger.error("USERSERVICEIMPL::resetPassword(4 params) => ERROR: {}", e.toString());
            return false;
        }
    }
}
