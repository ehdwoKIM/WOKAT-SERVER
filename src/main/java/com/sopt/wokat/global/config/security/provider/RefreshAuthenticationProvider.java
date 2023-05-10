package com.sopt.wokat.global.config.security.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class RefreshAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        throw new UnsupportedOperationException("Unimplemented method 'authenticate'");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        throw new UnsupportedOperationException("Unimplemented method 'supports'");
    }
}
