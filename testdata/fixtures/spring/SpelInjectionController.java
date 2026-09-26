package com.example.demo;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpelInjectionController {

    // Vulnerable: user-controlled request param evaluated directly as a
    // SpEL expression (CWE-94). An attacker can supply an expression like
    // T(java.lang.Runtime).getRuntime().exec('...') for RCE.
    @GetMapping("/greet")
    public String greet(@RequestParam String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression expression = parser.parseExpression(expr);
        return expression.getValue(String.class);
    }

    // Vulnerable: same sink, but the source flows through a local variable
    // first — the taint rule needs to track through the assignment, not
    // just match the call site directly.
    @GetMapping("/greet2")
    public String greet2(@RequestParam String name) {
        String template = "'Hello, ' + '" + name + "'";
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(template).getValue(String.class);
    }

    // Safe: expression is a fixed literal, not user input.
    @GetMapping("/safe")
    public String safe() {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression("'Hello, World'").getValue(String.class);
    }

    // Safe: request param is used as plain data, never passed to
    // parseExpression at all.
    @GetMapping("/echo")
    public String echo(@RequestParam String name) {
        return "Hello, " + name;
    }
}
