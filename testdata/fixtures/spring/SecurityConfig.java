package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    // Vulnerable: CSRF protection explicitly disabled (CWE-352). Reasonable
    // for a stateless, token-authenticated API, but a real footgun for a
    // cookie-session-based Spring MVC app, and disabled-by-default is a
    // common copy-pasted "fix" for a CSRF test failure rather than a
    // deliberate, reviewed decision.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        return http.build();
    }

    // Safe: CSRF left enabled (the Spring Security default).
    @Bean
    public SecurityFilterChain safeFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
