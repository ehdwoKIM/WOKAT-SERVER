package com.sopt.wokat.global.config.security.token;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

//! Refresh token 객체 리턴 
public class RefreshAuthenticationToken extends UsernamePasswordAuthenticationToken { 
    private RefreshAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public static RefreshAuthenticationToken of (String refreshToken) {
        return new RefreshAuthenticationToken(refreshToken, refreshToken);
    }
}