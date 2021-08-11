package com.ex.jwt.jwt.config;

public class SecurityConstants {
    public static final long EXPIRATION_TIME = 3_650; // IN DAYS
    public static final String TOKEN_PREFIX = "Bearer";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String GET_ARRAYS_LLC = "SOME NAME HERE";
    public static final String GET_ARRAYS_ADMINISTRATION = "NAME App";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to log in to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    public static final String[] PUBLIC_URLS = {"/", "/auth/**"};
//    public static final String[] PUBLIC_URLS = {"**"};
}
