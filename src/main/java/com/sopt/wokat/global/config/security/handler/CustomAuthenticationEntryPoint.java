package com.sopt.wokat.global.config.security.handler;

import static com.sopt.wokat.global.error.ErrorCode.*;

import java.io.IOException;
import java.io.OutputStream;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.sopt.wokat.global.error.ErrorResponse;

//! Authentication 실패 시 
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authenticationException) throws IOException {
        
        response.setStatus(JWT_INVALID.getStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        try (OutputStream os = response.getOutputStream()) {
			ObjectMapper objectMapper = new ObjectMapper();
			objectMapper.writeValue(os, ErrorResponse.of(JWT_INVALID));
			os.flush();
		}   
    }
}
