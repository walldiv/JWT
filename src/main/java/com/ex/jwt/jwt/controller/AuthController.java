package com.ex.jwt.jwt.controller;

import com.ex.jwt.jwt.JWTAuthProvider;
import com.ex.jwt.jwt.JWTTokenProvider;
import com.ex.jwt.jwt.exception.ExceptionHandling;
import com.ex.jwt.jwt.exception.exceptions.*;
import com.ex.jwt.jwt.model.PasswordReset;
import com.ex.jwt.jwt.model.User;
import com.ex.jwt.jwt.model.UserPrincipal;
import com.ex.jwt.jwt.service.IUserService;
import com.ex.jwt.jwt.service.PasswordResetRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import java.time.LocalDateTime;

import static com.ex.jwt.jwt.config.SecurityConstants.JWT_TOKEN_HEADER;


@Controller
//@CrossOrigin()
//@RequestMapping(path = {"/", "/auth"})
public class AuthController extends ExceptionHandling {
    private Logger logger = LoggerFactory.getLogger(this.getClass());
    private AuthenticationManager authenticationManager;
    private JWTAuthProvider authProvider;
    private JWTTokenProvider jwtTokenProvider;
    private IUserService userService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private PasswordResetRepository passwordRepo;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, JWTAuthProvider authProvider, JWTTokenProvider jwtTokenProvider, IUserService userService,
                          BCryptPasswordEncoder bCryptPasswordEncoder, PasswordResetRepository passwordRepo) {
        this.authenticationManager = authenticationManager;
        this.authProvider = authProvider;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.passwordRepo = passwordRepo;
    }

    @GetMapping("/hello")
    public String firstPage() {
        return "Hello world!";
    }

    @ResponseBody
    @PostMapping("/auth/register")
    public ResponseEntity register(@RequestBody User user) throws AlreadyExistsException, MessagingException {
        logger.info("USER INFO: => {}", user.toString());
        User tmp = this.userService.register(user.getFirstname(), user.getLastname(), user.getUsername(), user.getEmail());
        return new ResponseEntity("USER REGISTERATION SUCCESSFULLY", HttpStatus.OK);
    }

    @ResponseBody
    @PostMapping("/find")
    public ResponseEntity<User> findUser(@RequestBody User user) throws UsernameNotFoundException {
        logger.info("USER INFO: => {}", user.toString());
        try{
            User tmp = this.userService.findUserByUsername(user.getUsername());
            tmp.setPassword(null);
            return new ResponseEntity<>(tmp, HttpStatus.OK);
        } catch (UsernameNotFoundException e) {
            logger.error("USERNAME NOT FOUND EXCEPTION SHOULD BE THROWN");
            throw new UsernameNotFoundException("blah");
        }
    }

    @ResponseBody
    @GetMapping("/auth/verify")
    public ResponseEntity verifyRegistration(@RequestParam("email") String email) {
        logger.info("VERIFY REGISTRATION CALLED ==    EMAIL: {}", email);
        try{
            this.userService.verifyUser(email);
            return new ResponseEntity("REGISTRATION COMPLETE", HttpStatus.OK);
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity("PROBLEM VERIFYING YOUR ACCOUNT - CONTACT SYSTEM ADMINISTRATOR", HttpStatus.FORBIDDEN);
        }
    }

    @ResponseBody
    @GetMapping("/auth/resendverify")
    public ResponseEntity resendVerification(@RequestParam("email") String email) {
        logger.info("RESEND VERIFICATION REQUEST CALLED -   EMAIL: => {}", email);
        if(this.userService.resendVerificationEmail(email))
            return new ResponseEntity("REGISTRATION EMAIL RESENT TO YOUR EMAIL ADDRESS - PLEASE CHECK", HttpStatus.OK);
        else
            return new ResponseEntity("PROBLEM SENDING EMAIL - CONTACT SYSTEM ADMINISTRATOR", HttpStatus.FORBIDDEN);
    }

    @ResponseBody
    @PostMapping("/auth/login")
    public ResponseEntity<User> login(@RequestBody User user) throws LoginErrorException, AccountLockedOutException {
        logger.info("INCOMING LOGIN REQUEST => {}   {}", user.getUsername(), user.getPassword());
        User tmp = this.userService.findUserByUsername(user.getUsername());
        if(tmp.isIslockedout())
            throw new AccountLockedOutException("blah");
        String encodedPass = this.bCryptPasswordEncoder.encode(user.getPassword());
        Authentication auth = authenticate(user.getUsername(), user.getPassword());
        if(auth == null) {
            throw new LoginErrorException("blah");
        }
        if(tmp == null || tmp.isIslockedout() || !tmp.isIsaccountverified()) {
            logger.error("ERROR LOGGING IN User => {}", user.getUsername());
            throw new LoginErrorException("blah");
        }
        else {
            logger.info("AUTHENTICATION PASSED!!!    => {}", auth.getCredentials().toString());
            UserPrincipal userPrincipal = new UserPrincipal(tmp);
            HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
            tmp.setPassword(null);
            return new ResponseEntity<>(tmp, jwtHeader, HttpStatus.OK);
        }
    }


    @GetMapping(value = "/auth/passwordresettool_start")
    public PasswordReset resetMyPasswordStart(@RequestParam("token") String token) throws PasswordResetExpiredException {
        try{
            PasswordReset pwReset = this.passwordRepo.findByToken(token);
            if (pwReset == null || LocalDateTime.now().isAfter(pwReset.getExpirationTime())){
                logger.info("TIME OF REQUEST => {}          TIME OF MATCHING FUNCTION => {}", pwReset.getExpirationTime(), LocalDateTime.now());
                throw new PasswordResetExpiredException("blah");
            }
            else {
                return pwReset;
            }
        } catch (Exception e) {
            logger.error("AUTHCONTROLLER::resetMyPassword => EXCEPTION THROWN => {}", e.toString());
            throw new PasswordResetExpiredException("blah");
        }
    }

    @PostMapping(value = "/auth/passwordresettool_submit")
    public ResponseEntity resetMyPasswordSubmit(@RequestParam("token") PasswordReset inPwReset,
                        @RequestParam("oldpass") String oldPass, @RequestParam("newpass") String newPass){
        logger.info("PW RESET INCOMING => {}", inPwReset.toString());
        try {
            PasswordReset pwReset = this.passwordRepo.findByToken(inPwReset.getToken());
            if (pwReset == null || LocalDateTime.now().isAfter(pwReset.getExpirationTime())) {
                logger.info("TIME OF REQUEST => {}          TIME OF MATCHING FUNCTION => {}", pwReset.getExpirationTime(), LocalDateTime.now());
                throw new PasswordResetExpiredException("blah");
            }
            if(!this.userService.resetPassword(inPwReset.getEmail(),/* oldPass,*/ newPass, bCryptPasswordEncoder))
                return new ResponseEntity("FAILURE RESETTING PASSWORD - CONTACT SYSTEM ADMIN", HttpStatus.FORBIDDEN);
            else {
                this.passwordRepo.delete(pwReset);
                return new ResponseEntity("PASSWORD RESET SUCCESFULLY!", HttpStatus.OK);
            }
        } catch (PasswordResetExpiredException e) {
            return new ResponseEntity("FAILURE RESETTING PASSWORD - CONTACT SYSTEM ADMIN", HttpStatus.FORBIDDEN);
        }
    }

    @ResponseBody
    @GetMapping("/auth/resetpassword")
    public ResponseEntity resetPassword(@RequestParam("email") String email) {
        try{
            User tmp = this.userService.findUserByEmail(email);
            if(tmp == null)
                throw new UsernameNotFoundException("blah");
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity("PROBLEM SENDING EMAIL - CONTACT SYSTEM ADMINISTRATOR", HttpStatus.FORBIDDEN);
        }
        String rawToken = RandomStringUtils.randomAlphanumeric(10);
        String token = bCryptPasswordEncoder.encode(rawToken);
        LocalDateTime timestamp = LocalDateTime.now().plusMinutes(15l);
        PasswordReset passwordReset = new PasswordReset(token, email,timestamp);
        if(this.userService.sendPasswordResetEmail(passwordReset))
            return new ResponseEntity("RESET PASSWORD EMAIL SENT SUCCESSFULLY!!", HttpStatus.OK);
        else
            return new ResponseEntity("PROBLEM SENDING EMAIL - CONTACT SYSTEM ADMINISTRATOR", HttpStatus.FORBIDDEN);
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return headers;
    }

    private Authentication authenticate(String username, String password) {
        return authProvider.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
