package com.example.demo;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CorsConfig {

    // Vulnerable: wildcard origin on a controller that presumably serves
    // authenticated/session-bearing responses (CWE-942). A wildcard origin
    // combined with allowCredentials is rejected by browsers, but a bare
    // wildcard alone still lets any site read the response of a
    // credential-less request, and is rarely what was intended.
    @CrossOrigin(origins = "*")
    @GetMapping("/account")
    public String account() {
        return "account details";
    }

    // Safe: origin is a specific, allow-listed value.
    @CrossOrigin(origins = "https://app.example.com")
    @GetMapping("/account-safe")
    public String accountSafe() {
        return "account details";
    }

    // Vulnerable: array form with a wildcard buried among otherwise
    // specific origins.
    @CrossOrigin(origins = {"https://app.example.com", "*"})
    @GetMapping("/account-array")
    public String accountArray() {
        return "account details";
    }

    // Safe: array form with only specific, allow-listed origins.
    @CrossOrigin(origins = {"https://app.example.com", "https://admin.example.com"})
    @GetMapping("/account-array-safe")
    public String accountArraySafe() {
        return "account details";
    }
}
