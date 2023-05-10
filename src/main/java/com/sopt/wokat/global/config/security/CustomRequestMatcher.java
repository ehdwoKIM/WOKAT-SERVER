package com.sopt.wokat.global.config.security;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.http.HttpServletRequest;

public class CustomRequestMatcher implements RequestMatcher {
    private final OrRequestMatcher matcher;

    public CustomRequestMatcher(List<String> skipPaths) {
        final List<RequestMatcher> requestMatchers = skipPaths.stream()
                .map(AntPathRequestMatcher::new)
                .collect(Collectors.toList());
        
        this.matcher = new OrRequestMatcher(requestMatchers);
    }

    //! skip해야하는 url -> false
    @Override
    public boolean matches(HttpServletRequest request) {
        return !matcher.matches(request);
    }
}
