package org.license;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static spark.Spark.*;

/**
 * JWT License Server - Аналог YesApi для выдачи и проверки токенов
 */
public class JwtLicenseServer {

    private static final String APP_KEY = getEnv("APP_KEY", "B2740214CF6E4566231D50E5F703B38D");
    private static final String SECRET_KEY = getEnv("SECRET_KEY", "XWkeU1EuVa0SFjXwt0fO5HGm3FQfdovU6xlH68nRh9nGFgSd8ZgzyaNoUyM");

    private static final SecretKey JWT_SECRET_KEY = Keys.hmacShaKeyFor(
            SECRET_KEY.getBytes(StandardCharsets.UTF_8)
    );

    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        port(port);

        enableCORS();

        // Главный endpoint для всех POST запросов
        post("/", (req, res) -> {
            String service = req.queryParams("s");

            // Читаем тело запроса
            String body = req.body();
            System.out.println("📥 Получен запрос, service=" + service);
            System.out.println("📥 Тело запроса: " + body);

            if (service == null || service.isEmpty()) {
                return errorResponse("Missing parameter: s", 400);
            }

            // Парсим параметры из тела запроса
            Map<String, String> params = parseBodyParams(body);

            // Также проверяем query параметры (на всякий случай)
            if (req.queryParams("app_key") != null) {
                params.put("app_key", req.queryParams("app_key"));
                params.put("uid", req.queryParams("uid"));
                params.put("sub", req.queryParams("sub"));
                params.put("expTime", req.queryParams("expTime"));
                params.put("sign", req.queryParams("sign"));
                params.put("jwt_token", req.queryParams("jwt_token"));
            }

            System.out.println("📋 Распарсенные параметры: " + params.keySet());

            switch (service) {
                case "App.Common_Jwt.ApplyToken":
                    return handleApplyToken(params);
                case "App.Common_Jwt.VerifyToken":
                    return handleVerifyToken(params);
                default:
                    return errorResponse("Unknown service: " + service, 400);
            }
        });

        // Health check
        get("/health", (req, res) -> {
            Map<String, Object> response = new HashMap<>();
            response.put("status", "ok");
            response.put("timestamp", new Date().toString());
            response.put("service", "JWT License Server");
            return gson.toJson(response);
        });

        System.out.println("✅ JWT License Server запущен на порту " + port);
        System.out.println("📍 Endpoint: POST /?s=App.Common_Jwt.ApplyToken");
    }

    private static String handleApplyToken(Map<String, String> params) {
        Map<String, Object> response = new HashMap<>();

        try {
            String appKey = params.get("app_key");
            String uid = params.get("uid");
            String sub = params.get("sub");
            String expTimeStr = params.get("expTime");
            String sign = params.get("sign");

            System.out.println("🔍 Проверка параметров:");
            System.out.println("   app_key: " + appKey);
            System.out.println("   uid: " + uid);
            System.out.println("   sub: " + sub);
            System.out.println("   expTime: " + expTimeStr);
            System.out.println("   sign: " + sign);

            if (appKey == null || uid == null || sub == null || expTimeStr == null || sign == null) {
                return errorResponse("Missing required parameters: app_key, uid, sub, expTime, sign", 400);
            }

            if (!APP_KEY.equals(appKey)) {
                return errorResponse("Invalid app_key", 401);
            }

            int expTime = Integer.parseInt(expTimeStr);

            // Вычисляем ожидаемую подпись
            String signString = "app_key=" + appKey + "&expTime=" + expTime + "&sub=" + sub + "&uid=" + uid + "&" + SECRET_KEY;
            String expectedSign = md5(signString);

            System.out.println("🔐 Ожидаемая подпись: " + expectedSign);
            System.out.println("🔐 Полученная подпись: " + sign);

            if (!expectedSign.equalsIgnoreCase(sign)) {
                return errorResponse("Invalid sign", 401);
            }

            // Генерируем JWT токен
            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);
            Date expiration = new Date(nowMillis + expTime * 1000L);

            String jwtToken = Jwts.builder()
                    .setIssuedAt(now)
                    .setExpiration(expiration)
                    .setSubject(sub)
                    .claim("uid", uid)
                    .claim("app_key", appKey)
                    .signWith(JWT_SECRET_KEY, SignatureAlgorithm.HS256)
                    .compact();

            response.put("ret", 200);
            response.put("err_code", 0);
            response.put("err_msg", "");

            Map<String, Object> data = new HashMap<>();
            data.put("jwt_token", jwtToken);
            data.put("expires_in", expTime);
            data.put("token_type", "Bearer");
            response.put("data", data);

            System.out.println("✅ Токен выдан для " + uid);

        } catch (NumberFormatException e) {
            return errorResponse("Invalid expTime format", 400);
        } catch (Exception e) {
            e.printStackTrace();
            return errorResponse("Token generation failed: " + e.getMessage(), 500);
        }

        return gson.toJson(response);
    }

    private static String handleVerifyToken(Map<String, String> params) {
        Map<String, Object> response = new HashMap<>();

        try {
            String appKey = params.get("app_key");
            String jwtToken = params.get("jwt_token");

            if (appKey == null || jwtToken == null) {
                return errorResponse("Missing required parameters: app_key, jwt_token", 400);
            }

            if (!APP_KEY.equals(appKey)) {
                return errorResponse("Invalid app_key", 401);
            }

            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(JWT_SECRET_KEY)
                    .build()
                    .parseClaimsJws(jwtToken);

            Claims claims = jws.getBody();
            Date expiration = claims.getExpiration();
            Date now = new Date();

            if (expiration.before(now)) {
                return errorResponse("Token has expired", 403);
            }

            response.put("ret", 200);
            response.put("err_code", 0);
            response.put("err_msg", "");

            Map<String, Object> data = new HashMap<>();
            data.put("valid", true);
            data.put("uid", claims.get("uid"));
            data.put("sub", claims.getSubject());
            data.put("exp", expiration.getTime() / 1000);
            data.put("iat", claims.getIssuedAt().getTime() / 1000);
            response.put("data", data);

            System.out.println("✅ Токен проверен для " + claims.get("uid"));

        } catch (ExpiredJwtException e) {
            return errorResponse("Token has expired", 403);
        } catch (JwtException e) {
            return errorResponse("Invalid token signature", 401);
        } catch (Exception e) {
            e.printStackTrace();
            return errorResponse("Verification failed: " + e.getMessage(), 500);
        }

        return gson.toJson(response);
    }

    private static Map<String, String> parseBodyParams(String body) {
        Map<String, String> params = new HashMap<>();
        if (body == null || body.isEmpty()) {
            return params;
        }

        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                params.put(keyValue[0], keyValue[1]);
            }
        }
        return params;
    }

    private static String errorResponse(String message, int httpCode) {
        Map<String, Object> response = new HashMap<>();
        response.put("ret", httpCode);
        response.put("err_code", 1);
        response.put("err_msg", message);
        return gson.toJson(response);
    }

    private static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("MD5 failed", e);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }

    private static void enableCORS() {
        options("/*", (request, response) -> {
            response.header("Access-Control-Allow-Origin", "*");
            response.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            response.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            return "OK";
        });

        before((request, response) -> {
            response.header("Access-Control-Allow-Origin", "*");
            response.type("application/json");
        });
    }
}