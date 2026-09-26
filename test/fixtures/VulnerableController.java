package com.example.demo;

import java.sql.*;

public class VulnerableController {

    // Classic SQL injection via string concatenation.
    public ResultSet search(Connection conn, String userInput) throws SQLException {
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM products WHERE name = '" + userInput + "'";
        return stmt.executeQuery(query);
    }

    // Command injection via Runtime.exec with unsanitized input.
    public void runCommand(String userInput) throws Exception {
        Runtime.getRuntime().exec("ping " + userInput);
    }

    // Hardcoded credential.
    private static final String DB_PASSWORD = "SuperSecret123!";
}
