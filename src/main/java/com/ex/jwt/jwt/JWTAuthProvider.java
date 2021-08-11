package com.ex.jwt.jwt;

import com.ex.jwt.jwt.exception.exceptions.AccountLockedOutException;
import com.ex.jwt.jwt.model.User;
import com.ex.jwt.jwt.model.UserPrincipal;
import com.ex.jwt.jwt.service.IUserService;
import com.ex.jwt.jwt.service.LoginAttemptService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class JWTAuthProvider implements AuthenticationProvider {
    private Logger logger = LoggerFactory.getLogger(this.getClass());
    private IUserService userService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private LoginAttemptService loginAttemptService;

    @Autowired
    public JWTAuthProvider(IUserService userService, BCryptPasswordEncoder bCryptPasswordEncoder, LoginAttemptService loginAttemptService) {
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        logger.info("AUTHENTICATE => {}    {}", username, password);
        User tmp = new User();
        try{
            tmp = this.userService.findUserByUsername(username);
            if(tmp == null)
                return null;
            } catch (UsernameNotFoundException e) {
                return null;
            }
        if(bCryptPasswordEncoder.matches(password, tmp.getPassword())){
            logger.info("PASSWORDMATCHES!!!");
            final UserPrincipal principal = new UserPrincipal(tmp);
            final Authentication auth = new UsernamePasswordAuthenticationToken(principal, password, principal.getAuthorities());
            return auth;
        } else{
            logger.info("PASSWORD DOESNT MATCH");
            try {
                validateLoginAttempt(tmp);
            } catch (AccountLockedOutException e) {
                this.userService.saveUser(tmp);
            }
            logger.info("USER LOCKED OUT STATUS => {}", tmp.isIslockedout());
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return false;
    }

    /**
     *
     * @param user
     * if User.isNotLocked & has NOT exceeded max attempts. - which increments the users count by 1
     */
    private void validateLoginAttempt(User user) throws AccountLockedOutException {
        if (!user.isIslockedout()){
            if(loginAttemptService.hasExceededMaxAttempts(user.getUsername())) {
                loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
                logger.error("TOO MANY LOGIN ATTEMPTS - ACCOUNT IS NOW LOCKED");
                user.setIslockedout(true);
                throw new AccountLockedOutException("blah");
            } else{
                logger.info("USERS FAILED ATTEMPTS IS INCREMENTED BY 1");
                loginAttemptService.incrementFailedLoginAttempt(user.getUsername());
                user.setIslockedout(false);
            }
        } else{
            logger.error("ACCOUNT IS LOCKED - UNABLE TO LOGIN");
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
            user.setIslockedout(true);
            throw new AccountLockedOutException("blah");
        }
    }
}
