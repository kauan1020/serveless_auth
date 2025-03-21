package com.example;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class AuthHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private static final String DB_HOST = System.getenv("DB_HOST");
    private static final String DB_NAME = System.getenv("DB_NAME");
    private static final String DB_USER = System.getenv("DB_USER");
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    private static final String JDBC_URL = "jdbc:postgresql://" + DB_HOST + "/" + DB_NAME;

    private static final String SECRET_KEY = System.getenv("JWT_SECRET");
    private static final SignatureAlgorithm ALGORITHM = SignatureAlgorithm.HS256;

    private static Connection conn;

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        try {
            context.getLogger().log("Recebendo evento: " + mapper.writeValueAsString(event));

            Map<String, Object> body;
            Object rawBody = event.get("body");

            if (rawBody instanceof String) {
                body = mapper.readValue((String) rawBody, Map.class);
            } else if (rawBody instanceof Map) {
                body = (Map<String, Object>) rawBody;
            } else {
                body = new HashMap<>();
            }

            String cpf = (String) body.get("cpf");
            if (cpf == null || cpf.trim().isEmpty()) {
                response.put("statusCode", 400);
                response.put("headers", headers);
                ObjectNode errorBody = mapper.createObjectNode();
                errorBody.put("message", "CPF é obrigatório");
                response.put("body", errorBody.toString());
                return response;
            }

            Map<String, Object> userData = getUserByCPF(cpf);
            if (userData == null) {
                response.put("statusCode", 404);
                response.put("headers", headers);
                ObjectNode errorBody = mapper.createObjectNode();
                errorBody.put("message", "Usuário não encontrado");
                response.put("body", errorBody.toString());
                return response;
            }

            String jwtToken = generateJWT(userData);

            response.put("statusCode", 200);
            response.put("headers", headers);
            ObjectNode successBody = mapper.createObjectNode();
            successBody.put("token", jwtToken);
            successBody.put("expires_in", 7200);
            response.put("body", successBody.toString());

        } catch (Exception e) {
            context.getLogger().log("Erro: " + e.getMessage());
            response.put("statusCode", 500);
            response.put("headers", headers);
            ObjectNode errorBody = mapper.createObjectNode();
            errorBody.put("message", "Erro interno do servidor");
            response.put("body", errorBody.toString());
        }

        return response;
    }

    private Connection getConnection() {
        try {
            if (conn == null || conn.isClosed()) {
                Class.forName("org.postgresql.Driver");
                conn = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
            }
        } catch (Exception e) {
            System.err.println("Erro ao conectar ao banco: " + e.getMessage());
            return null;
        }
        return conn;
    }

    private Map<String, Object> getUserByCPF(String cpf) {
        try {
            Connection connection = getConnection();
            if (connection == null) {
                return null;
            }

            String sql = "SELECT id, username, email FROM users WHERE cpf = ?";
            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                stmt.setString(1, cpf);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        Map<String, Object> userData = new HashMap<>();
                        userData.put("id", rs.getInt("id"));
                        userData.put("username", rs.getString("username"));
                        userData.put("email", rs.getString("email"));
                        return userData;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erro ao consultar banco: " + e.getMessage());
            try {
                if (conn != null) {
                    conn.close();
                    conn = null;
                }
            } catch (Exception ignored) {}
            return null;
        }
        return null;
    }

    private String generateJWT(Map<String, Object> userData) {
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() + 7200 * 1000);
        return Jwts.builder()
                .setSubject(userData.get("id").toString())
                .claim("username", userData.get("username"))
                .claim("email", userData.get("email"))
                .setExpiration(expirationTime)
                .signWith(ALGORITHM, SECRET_KEY.getBytes())
                .compact();
    }
}