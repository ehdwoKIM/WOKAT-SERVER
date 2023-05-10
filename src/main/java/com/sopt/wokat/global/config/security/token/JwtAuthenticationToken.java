package com.sopt.wokat.global.config.security.token;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

//* 사용자의 정보 담은 객체 리턴
public class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken {
    private JwtAuthenticationToken(Object principal, Object credentials,
            Collection<? extends GrantedAuthority> authorities) {  //! 유저의 권한정보 담긴 컬렉션 ex) ROLE_ADMIN, ROLE_USER
        super(principal, credentials, authorities);
    }

    private JwtAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    ///! JwtAuthenticationToken 인스턴스 생성하는 정적 팩토리 메소드 
    public static JwtAuthenticationToken of(String jwt) {
        return new JwtAuthenticationToken(jwt, jwt);
    }
    
    ///! JwtAuthenticationToken 인스턴스 생성하는 정적 팩토리 메소드 
    public static JwtAuthenticationToken of(Object principal, Object credentials,
            Collection<? extends GrantedAuthority> authorities) {
        return new JwtAuthenticationToken(principal, credentials, authorities);
    }
}
