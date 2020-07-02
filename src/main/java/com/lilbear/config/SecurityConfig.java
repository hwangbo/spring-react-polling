package com.lilbear.config;

import com.lilbear.security.JWTAuthenticationFilter;
import com.lilbear.security.JwtAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
    1. @EnableWebSecurity
        프로젝트에서 웹 보안을 가능하게 하는 기본 Spring Security Annotation.
    2. @EnableGlobalMethodSecurity
        메소드 보안을 위해 사용.
    3. WebSecurityConfigurerAdapter
        Spring Security 의 WebSecurityConfigurer 인터페이스를 구현함.
        사용자 정의 보안 구성을 제공하기 위해서 메소드를 확장하고 재정의함.
    4. JwtAuthenticationEntryPoint
        인증절차 없이 자원에 액세스 시도하는 클라이언트에게 401 오류 반환.
        Spring Security 의 AuthenticationEntryPoint 인터페이스를 구현함.
    5. JwtAuthenticationFilter
        JWT 인증 토큰을 읽어, 유효성 검사 후 토큰과 관련된 세부사항을 로드함.
    6. AuthenticationManagerBuilder / AuthenticationManager
        사용자 인증을 위한 Spring Security 를 생성하는데 사용.
        passwordEncoder 를 사용.
    7. HttpSecurity Config
        HttpSecurity 구성과 같은 보안기능을 구성하는데 사용됨.
        csrf, sessionManagement 등의 보호기능 및 규칙을 추가할 수 있음.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

    @Bean
    public JWTAuthenticationFilter jwtAuthenticationFilter() {
        return new JWTAuthenticationFilter();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors()
                .and()
                .csrf()
                .disable()
                .exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler)
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/", "/favicon.ico", "/**/*.png", "/**/*.gif", "/**/*.svg", "/**/*.jpg", "/**/*.html", "/**/*.css", "/**/*.js")
                .permitAll()
                .antMatchers("/api/auth/**")
                .permitAll()
                .antMatchers("/api/user/checkUsernameAvailability", "/api/user/checkEmailAvailability")
                .permitAll()
                .anyRequest()
                .authenticated();

        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
