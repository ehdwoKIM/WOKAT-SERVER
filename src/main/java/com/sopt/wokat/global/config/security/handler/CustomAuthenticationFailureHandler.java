package com.sopt.wokat.global.config.security.handler;

import static com.sopt.wokat.global.error.ErrorCode.*;

import java.io.IOException;
import java.io.OutputStream;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.sopt.wokat.global.error.ErrorResponse;


//! Filter 통과 못할 시 실패처리 핸들러 
@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
            
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            try (OutputStream os = response.getOutputStream()) {
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.writeValue(os, ErrorResponse.of(ACCOUNT_MISMATCH));
                os.flush();
            }
    }
}
