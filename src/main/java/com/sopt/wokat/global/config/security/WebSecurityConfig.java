package com.sopt.wokat.global.config.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;

import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;
import com.sopt.wokat.global.config.security.filter.CustomExceptionHandleFilter;
import com.sopt.wokat.global.config.security.filter.CustomUsernamePasswordAuthenticationFilter;
import com.sopt.wokat.global.config.security.filter.JwtAuthenticationFilter;
import com.sopt.wokat.global.config.security.filter.RefreshAuthenticationFilter;
import com.sopt.wokat.global.config.security.handler.CustomAuthenticationEntryPoint;
import com.sopt.wokat.global.config.security.handler.CustomAuthenticationFailureHandler;
import com.sopt.wokat.global.config.security.handler.CustomAuthenticationSuccessHandler;
import com.sopt.wokat.global.config.security.provider.JwtAuthenticationProvider;
import com.sopt.wokat.global.util.JwtUtil;
import com.sopt.wokat.domain.user.service.CustomUserDetailService;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final Logger LOGGER = LogManager.getLogger(this.getClass());
    
    private final JwtUtil jwtUtil;
    private final CustomUserDetailService jwtUserDetailService;

    //! Provider
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    //! Handler
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
	private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    //! Filter
	private final CustomExceptionHandleFilter customExceptionHandleFilter;

    //! authenticationManager 관련
    private final AuthenticationConfiguration authenticationConfiguration;

    
    private static final String[] AUHT_WHITELIST_SWAGGER = {
        "/swagger-resources/**",
        "/swagger/**",
        "/swagger-ui/**",
        "/swagger-ui.html",
        "/swagger-ui/index.html",
        "/v3/api-docs/**",
        "/webjars/**"
    };
    
    private static final String[] AUTH_WHITELIST_STATIC = {
     //   "/static/css/**", 
      //  "/static/js/**", 
      //  "*.ico"
    };
    
    private static final String[] AUTH_WHITELIST = {
        "/member/login/kakao"
    };


    @Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}


    @Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {

		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();

		daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());
		daoAuthenticationProvider.setUserDetailsService(jwtUserDetailService);

		return daoAuthenticationProvider;

	}


    @Bean
	public AuthenticationEntryPointFailureHandler authenticationEntryPointFailureHandler() {
		return new AuthenticationEntryPointFailureHandler(customAuthenticationEntryPoint);
	}


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) 
        throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    //* Filter1 - jwtAuthenticationFilter 설정 
    //! spring security skip해야하는 url 확인 후 filter 객체 생성 
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {

        final List<String> skipPaths = new ArrayList<>();

        skipPaths.addAll(Arrays.stream(AUHT_WHITELIST_SWAGGER).collect(Collectors.toList()));
        skipPaths.addAll(Arrays.stream(AUTH_WHITELIST_STATIC).collect(Collectors.toList()));
        skipPaths.addAll(Arrays.stream(AUTH_WHITELIST).collect(Collectors.toList()));

        
        final RequestMatcher matcher = new CustomRequestMatcher(skipPaths);
        final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(matcher, jwtUtil);

        filter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        filter.setAuthenticationFailureHandler(authenticationEntryPointFailureHandler());

        return filter;

    }

    //* Filter2 - CustomUsernamePasswordAuthenticationFilter 설정 
    @Bean
    public CustomUsernamePasswordAuthenticationFilter customUsernamePasswordAuthenticationFilter () 
        throws Exception {

        final CustomUsernamePasswordAuthenticationFilter filter = new CustomUsernamePasswordAuthenticationFilter();

        filter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        filter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(customAuthenticationFailureHandler);
        
        return filter;
        
    }

    //* Filter3 - RefreshAuthenticationFilter 설정
    @Bean
    public RefreshAuthenticationFilter refreshAuthenticationFilter () 
        throws Exception {

        final RefreshAuthenticationFilter filter = new RefreshAuthenticationFilter();

        filter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        filter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(customAuthenticationFailureHandler);

        return filter;

    }



    //* HTTP 요청 이전에
    //! spring security 제외 
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() { 

        return (web) -> web
                            .ignoring()
                            .requestMatchers(AUHT_WHITELIST_SWAGGER)
                            .requestMatchers(AUTH_WHITELIST_STATIC);
    
    }
    

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        
        //! 세션 정보를 유지하지 않고, 모든 요청에 대해 인증 토큰을 사용하여 인증을 처리하기 위해 
        //* 즉, 세션 기반 인증 대신 REST-API에서 토큰 기반 인증(JWT) 사용 위해 
        http
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        
        //! rest-api에서 세션 기반 인증 대신 토큰 인증 사용 위해 로그아웃, 폼로그인, HTTP 기반 인증 기능 disable 
        http
            .logout(LogoutConfigurer<HttpSecurity>::disable)   
            .formLogin(AbstractAuthenticationFilterConfigurer::disable)
            .httpBasic(HttpBasicConfigurer<HttpSecurity>::disable);

        
        http
            .csrf(AbstractHttpConfigurer::disable)  //! CSRF(Cross-Site Request Forgery) 공격 방지 기능 비활성화
            .cors(cors -> cors.configurationSource(configurationSource()))  //! cors 설정 
            .authorizeHttpRequests(authorize -> {
                authorize
                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                        .requestMatchers(AUTH_WHITELIST).permitAll()
                        // .requestMatchers("/admin/**").hasRole("ADMIN")   
                        .anyRequest().authenticated();  //! 모든 요청 인증 필요함 
            });

        
        //! provider 추가
        http
            .authenticationProvider(jwtAuthenticationProvider)
            .authenticationProvider(daoAuthenticationProvider());
        

        //! filter 추가
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(customExceptionHandleFilter, JwtAuthenticationFilter.class)
            .addFilterBefore(customUsernamePasswordAuthenticationFilter(), JwtAuthenticationFilter.class)
           // .addFilterBefore(resetPasswordCodeAuthenticationFilter(), JwtAuthenticationFilter.class)
            .addFilterBefore(refreshAuthenticationFilter(), JwtAuthenticationFilter.class);


        return http.build();
        
    }


    @Bean
    public CorsConfigurationSource configurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000")); //! TO-DO 클라이언트 도메인 추가하기 
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));
        //configuration.setExposedHeaders(Arrays.asList("Content-Type", "Authorization"));

        configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);  //! CORS preflight 요청 1시간으로 설정 
        

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);

		return source;

    }

}
