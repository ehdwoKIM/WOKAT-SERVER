package com.sopt.wokat.global.config.security.handler;

import static com.sopt.wokat.global.result.ResultCode.*;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import com.sopt.wokat.domain.user.dto.JwtDTO;
import com.sopt.wokat.domain.user.dto.JwtResponseDTO;
import com.sopt.wokat.global.result.ResultCode;
import com.sopt.wokat.global.result.ResultResponse;
import com.sopt.wokat.global.util.JwtUtil;


@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private Map<String, ResultCode> resultCodeMap;
    private final ResultCode DEFAULT_RESULT_CODE = LOGIN_SUCCESS;
    //private final RefreshTokenService refreshTokenService;

    @Value("${jwt.refresh-token.expire-length}")
	private long REFRESH_TOKEN_EXPIRES;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain,
        Authentication authentication) throws IOException, ServletException {
        this.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
    Authentication authentication) throws IOException, ServletException {

        final JwtDTO jwtDTO = jwtUtil.generateJwtDTO(authentication);

        //! [TO-DO] refresh token Redis에 저장하는 로직 추가하기

        final JwtResponseDTO jwtResponseDTO = JwtResponseDTO.builder()
                .type(jwtDTO.getType())
                .accessToken(jwtDTO.getAccessToken())
                .build();

        //! [TO-DO] refresh token add cookie
        //addCookie(response, jwtDto.getRefreshToken());
        
        final ResultCode resultCode = getResultCode(request);

        response.setStatus(resultCode.getStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        try (OutputStream os = response.getOutputStream()) {

			ObjectMapper objectMapper = new ObjectMapper();
			objectMapper.writeValue(os, ResponseEntity.ok(ResultResponse.of(resultCode, jwtResponseDTO)).getBody());
			os.flush();
            
		}

    }

    public void setResultCodeMap(Map<String, ResultCode> resultCodeMap) {
        this.resultCodeMap = resultCodeMap;
    }

    //! Result code 반환 
    protected ResultCode getResultCode(HttpServletRequest request) {

        if (resultCodeMap != null && resultCodeMap.containsKey(request.getRequestURI())) {
            return resultCodeMap.get(request.getRequestURI());
        } else {
            return DEFAULT_RESULT_CODE;
        }

    }


    /* 
    protected void addCookie(HttpServletResponse response, String refreshTokenString) {
		final Cookie cookie = new Cookie("refreshToken", refreshTokenString);

		cookie.setMaxAge(REFRESH_TOKEN_EXPIRES);

		// cookie.setSecure(true); https 미지원
		cookie.setHttpOnly(true);
		cookie.setPath("/");
		cookie.setDomain(COOKIE_DOMAIN);

		response.addCookie(cookie);
	}
    */
    
}