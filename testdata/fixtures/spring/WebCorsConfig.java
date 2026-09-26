package com.example.demo;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebCorsConfig implements WebMvcConfigurer {

    // Vulnerable: global CORS config allowing any origin (CWE-942). This
    // is the more common real-world shape than the per-controller
    // @CrossOrigin annotation — one line in a config class opens CORS for
    // every endpoint in the app.
    public void addCorsMappingsVulnerable(CorsRegistry registry) {
        registry.addMapping("/**").allowedOrigins("*");
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // Safe: allow-listed to a specific, known origin.
        registry.addMapping("/**").allowedOrigins("https://app.example.com");
    }
}
