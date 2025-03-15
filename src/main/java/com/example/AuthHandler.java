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

    // Valores fixos (hardcoded) em vez de variáveis de ambiente
    private static final String DB_HOST = "techdatabase.cxpkgzr59ec4.us-east-1.rds.amazonaws.com";
    private static final String DB_NAME = "postgres";
    private static final String DB_USER = "postgres";
    private static final String DB_PASSWORD = "postgres";
    private static final String JDBC_URL = "jdbc:postgresql://" + DB_HOST + "/" + DB_NAME;

    // Chave secreta para JWT
    private static final String SECRET_KEY = "chave_super_secreta";
    private static final SignatureAlgorithm ALGORITHM = SignatureAlgorithm.HS256;

    // Conexão reutilizável
    private static Connection conn;

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        try {
            // Log do evento
            context.getLogger().log("Recebendo evento: " + mapper.writeValueAsString(event));

            // Extrair o corpo da requisição
            Map<String, Object> body;
            Object rawBody = event.get("body");

            if (rawBody instanceof String) {
                body = mapper.readValue((String) rawBody, Map.class);
            } else if (rawBody instanceof Map) {
                body = (Map<String, Object>) rawBody;
            } else {
                body = new HashMap<>();
            }

            // Verificar se o CPF está presente
            String cpf = (String) body.get("cpf");
            if (cpf == null || cpf.trim().isEmpty()) {
                response.put("statusCode", 400);
                response.put("headers", headers);

                ObjectNode errorBody = mapper.createObjectNode();
                errorBody.put("message", "CPF é obrigatório");
                response.put("body", errorBody.toString());

                return response;
            }

            // Consultar usuário por CPF
            Map<String, Object> userData = getUserByCPF(cpf);
            if (userData == null) {
                response.put("statusCode", 404);
                response.put("headers", headers);

                ObjectNode errorBody = mapper.createObjectNode();
                errorBody.put("message", "Usuário não encontrado");
                response.put("body", errorBody.toString());

                return response;
            }

            // Gerar JWT
            String jwtToken = generateJWT(userData);

            // Montar resposta de sucesso
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

    private Connection getConnection() throws Exception {
        if (conn == null || conn.isClosed()) {
            // Carregar o driver JDBC
            Class.forName("org.postgresql.Driver");

            // Estabelecer conexão
            conn = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
        }
        return conn;
    }

    private Map<String, Object> getUserByCPF(String cpf) {
        try {
            Connection connection = getConnection();
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
            return null;
        } catch (Exception e) {
            System.err.println("Erro ao consultar banco: " + e.getMessage());
            // Em caso de erro, fechar a conexão para tentar novamente na próxima chamada
            try {
                if (conn != null) {
                    conn.close();
                    conn = null;
                }
            } catch (Exception ignored) {}
            return null;
        }
    }

    private String generateJWT(Map<String, Object> userData) {
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() + 7200 * 1000); // 2 horas em milissegundos

        return Jwts.builder()
                .setSubject(userData.get("id").toString())
                .claim("username", userData.get("username"))
                .claim("email", userData.get("email"))
                .setExpiration(expirationTime)
                .signWith(ALGORITHM, SECRET_KEY.getBytes())
                .compact();
    }
}