package com.ex.jwt.jwt.exception;

import com.ex.jwt.jwt.exception.exceptions.*;
import com.ex.jwt.jwt.model.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * This class is used for all exception handling for your rest controllers.  The annotation allows for
 * RestControllers to extend this class and utilize it as a first-stop method for CUSTOM exception handling.
 */
@RestControllerAdvice
public class ExceptionHandling {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final String ACCOUNT_LOCKED = "Your account has been locked. Please contact administration";
    private static final String METHOD_IS_NOT_ALLOWED = "This request method is not allowed on this endpoint. Please send a '%s' request";
    private static final String INTERNAL_SERVER_ERROR_MSG = "An error occurred while processing the request";
    private static final String INCORRECT_CREDENTIALS = "Username / password incorrect. Please try again";
    private static final String ACCOUNT_DISABLED = "Your account has been disabled. If this is an error, please contact administration";
    private static final String ERROR_PROCESSING_FILE = "Error occurred while processing file";
    private static final String NOT_ENOUGH_PERMISSION = "You do not have enough permission";
    public static final String  PASSWORD_RESET_EXPIRED = "Your password reset request has expired.  Please contact system administrator for support.";
    public static final String ERROR_PATH = "/error";

    @ExceptionHandler(AlreadyExistsException.class)
    public ResponseEntity<HttpResponse> alreadyExistsException(AlreadyExistsException exception) {
        return createHttpResponse(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<HttpResponse> usernameNotFoundException(UsernameNotFoundException exception) {
        return createHttpResponse(HttpStatus.NOT_FOUND, INCORRECT_CREDENTIALS);
    }

    @ExceptionHandler(LoginErrorException.class)
    public ResponseEntity<HttpResponse> loginErrorException(LoginErrorException exception){
        return createHttpResponse(HttpStatus.UNAUTHORIZED, INCORRECT_CREDENTIALS);
    }

    @ExceptionHandler(AccountLockedOutException.class)
    public ResponseEntity<HttpResponse> accountLockedOutException(AccountLockedOutException exception) {
        return createHttpResponse(HttpStatus.FORBIDDEN, ACCOUNT_LOCKED);
    }
    @ExceptionHandler(PasswordResetExpiredException .class)
    public ResponseEntity<HttpResponse> passwordResetExpired(PasswordResetExpiredException exception) {
        return createHttpResponse(HttpStatus.FORBIDDEN, PASSWORD_RESET_EXPIRED);
    }


    private ResponseEntity<HttpResponse> createHttpResponse(HttpStatus httpStatus, String message) {
        HttpResponse response = new HttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(),
                message.toUpperCase());
        return new ResponseEntity<>(response, httpStatus);
    }
}
