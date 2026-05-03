package org.license;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static spark.Spark.*;

/**
 * JWT License Server - Аналог YesApi для выдачи и проверки токенов
 * Полностью бесплатный, работает на Render.com
 */
public class JwtLicenseServer {

    // ==================== КОНФИГУРАЦИЯ ====================
    // Эти переменные должны быть установлены в Render.com как Environment Variables
    // Для локального тестирования можно задать значения по умолчанию

    private static final String APP_KEY = getEnv("APP_KEY", "B2740214CF6E4566231D50E5F703B38D");
    private static final String SECRET_KEY = getEnv("SECRET_KEY", "XWkeU1EuVa0SFjXwt0fO5HGm3FQfdovU6xlH68nRh9nGFgSd8ZgzyaNoUyM");
    private static final String PUBLIC_KEY = getEnv("PUBLIC_KEY", "MyPublicKeyForLicenseVerification");

    // Ключ для подписи JWT (генерируется из SECRET_KEY)
    private static final SecretKey JWT_SECRET_KEY = Keys.hmacShaKeyFor(
            SECRET_KEY.getBytes(StandardCharsets.UTF_8)
    );

    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    // ==================== MAIN ====================

    public static void main(String[] args) {
        // Настройка порта для Render.com
        int port = getEnv("PORT", "8080") != null ? Integer.parseInt(getEnv("PORT", "8080")) : 8080;
        port(port);

        // Включаем CORS для запросов с клиентских ПК
        enableCORS();

        // Настройка маршрутов
        setupRoutes();

        System.out.println("✅ JWT License Server запущен на порту " + port);
        System.out.println("📋 APP_KEY: " + APP_KEY);
        System.out.println("🔐 Метод подписи: HS256");
        System.out.println("📍 Endpoints:");
        System.out.println("   POST /?s=App.Common_Jwt.ApplyToken  - выдача токена");
        System.out.println("   POST /?s=App.Common_Jwt.VerifyToken - проверка токена");
        System.out.println("   GET  /health - проверка здоровья сервера");
    }

    // ==================== НАСТРОЙКА МАРШРУТОВ ====================

    private static void setupRoutes() {

        // Health check для Render.com
        get("/health", (req, res) -> {
            Map<String, Object> response = new HashMap<>();
            response.put("status", "ok");
            response.put("timestamp", Instant.now().toString());
            response.put("service", "JWT License Server");
            return gson.toJson(response);
        });

        // Главный endpoint - имитация YesApi
        post("/", (req, res) -> {
            String service = req.queryParams("s");
            String body = req.body();

            if (service == null || service.isEmpty()) {
                return errorResponse("Missing parameter: s", 400);
            }

            // Парсим параметры из body
            Map<String, String> params = parseBodyParams(body);

            switch (service) {
                case "App.Common_Jwt.ApplyToken":
                    return handleApplyToken(params);
                case "App.Common_Jwt.VerifyToken":
                    return handleVerifyToken(params);
                default:
                    return errorResponse("Unknown service: " + service, 400);
            }
        });

        // Обработка 404
        notFound((req, res) -> {
            return errorResponse("Endpoint not found", 404);
        });

        // Обработка ошибок
        exception(Exception.class, (e, req, res) -> {
            e.printStackTrace();
            res.status(500);
            res.body(errorResponse("Internal server error: " + e.getMessage(), 500));
        });
    }

    // ==================== ОБРАБОТЧИКИ ЗАПРОСОВ ====================

    /**
     * Обработка запроса на выдачу токена (аналог App.Common_Jwt.ApplyToken)
     * Параметры:
     *   - app_key: публичный ключ приложения
     *   - uid: уникальный идентификатор пользователя
     *   - sub: субъект (назначение токена)
     *   - expTime: время жизни в секундах
     *   - sign: MD5 подпись (app_key + uid + sub + expTime + app_secret)
     */
    private static String handleApplyToken(Map<String, String> params) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 1. Проверяем обязательные параметры
            String appKey = params.get("app_key");
            String uid = params.get("uid");
            String sub = params.get("sub");
            String expTimeStr = params.get("expTime");
            String sign = params.get("sign");

            if (appKey == null || uid == null || sub == null || expTimeStr == null || sign == null) {
                return errorResponse("Missing required parameters: app_key, uid, sub, expTime, sign", 400);
            }

            // 2. Проверяем app_key
            if (!APP_KEY.equals(appKey)) {
                return errorResponse("Invalid app_key", 401);
            }

            // 3. Проверяем подпись
            int expTime = Integer.parseInt(expTimeStr);
            String signString = "app_key=" + appKey + "&expTime=" + expTime + "&sub=" + sub + "&uid=" + uid + "&" + SECRET_KEY;
            String expectedSign = md5(signString);

            if (!expectedSign.equalsIgnoreCase(sign)) {
                System.out.println("❌ Неверная подпись!");
                System.out.println("   Ожидали: " + expectedSign);
                System.out.println("   Получили: " + sign);
                return errorResponse("Invalid sign", 401);
            }

            // 4. Генерируем JWT токен
            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);
            Date expiration = new Date(nowMillis + expTime * 1000L);

            String jwtToken = Jwts.builder()
                    .setHeaderParam("typ", "JWT")
                    .setIssuedAt(now)
                    .setExpiration(expiration)
                    .setSubject(sub)
                    .claim("uid", uid)
                    .claim("app_key", appKey)
                    .claim("iat", nowMillis / 1000)
                    .claim("exp", expiration.getTime() / 1000)
                    .signWith(JWT_SECRET_KEY, SignatureAlgorithm.HS256)
                    .compact();

            // 5. Формируем ответ в формате YesApi
            response.put("ret", 200);
            response.put("err_code", 0);
            response.put("err_msg", "");

            Map<String, Object> data = new HashMap<>();
            data.put("jwt_token", jwtToken);
            data.put("expires_in", expTime);
            data.put("token_type", "Bearer");
            response.put("data", data);

            System.out.println("✅ Выдан токен для uid=" + uid + ", sub=" + sub + ", expTime=" + expTime + " сек");

        } catch (NumberFormatException e) {
            return errorResponse("Invalid expTime format", 400);
        } catch (Exception e) {
            e.printStackTrace();
            return errorResponse("Token generation failed: " + e.getMessage(), 500);
        }

        return gson.toJson(response);
    }

    /**
     * Обработка запроса на проверку токена (аналог App.Common_Jwt.VerifyToken)
     * Параметры:
     *   - app_key: публичный ключ приложения
     *   - jwt_token: JWT токен для проверки
     */
    private static String handleVerifyToken(Map<String, String> params) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 1. Проверяем обязательные параметры
            String appKey = params.get("app_key");
            String jwtToken = params.get("jwt_token");

            if (appKey == null || jwtToken == null) {
                return errorResponse("Missing required parameters: app_key, jwt_token", 400);
            }

            // 2. Проверяем app_key
            if (!APP_KEY.equals(appKey)) {
                return errorResponse("Invalid app_key", 401);
            }

            // 3. Проверяем и парсим JWT
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(JWT_SECRET_KEY)
                    .build()
                    .parseClaimsJws(jwtToken);

            Claims claims = jws.getBody();
            Date expiration = claims.getExpiration();
            Date now = new Date();

            // 4. Проверяем, не истёк ли токен
            if (expiration.before(now)) {
                return errorResponse("Token has expired", 403);
            }

            // 5. Формируем успешный ответ
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

            System.out.println("✅ Проверен токен для uid=" + claims.get("uid") + ", действителен до " + expiration);

        } catch (ExpiredJwtException e) {
            return errorResponse("Token has expired", 403);
        } catch (JwtException e) {
            System.out.println("❌ Ошибка верификации JWT: " + e.getMessage());
            return errorResponse("Invalid token signature", 401);
        } catch (Exception e) {
            e.printStackTrace();
            return errorResponse("Verification failed: " + e.getMessage(), 500);
        }

        return gson.toJson(response);
    }

    // ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

    /**
     * Формирует ответ с ошибкой (в формате YesApi)
     */
    private static String errorResponse(String message, int httpCode) {
        Map<String, Object> response = new HashMap<>();
        response.put("ret", httpCode);
        response.put("err_code", 1);
        response.put("err_msg", message);
        return gson.toJson(response);
    }

    /**
     * Парсит параметры из x-www-form-urlencoded тела запроса
     */
    private static Map<String, String> parseBodyParams(String body) {
        Map<String, String> params = new HashMap<>();
        if (body == null || body.isEmpty()) {
            return params;
        }

        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                String key = decodeUrl(keyValue[0]);
                String value = decodeUrl(keyValue[1]);
                params.put(key, value);
            }
        }
        return params;
    }

    /**
     * Простое декодирование URL (для параметров)
     */
    private static String decodeUrl(String encoded) {
        try {
            return java.net.URLDecoder.decode(encoded, "UTF-8");
        } catch (Exception e) {
            return encoded;
        }
    }

    /**
     * MD5 хеширование (совместимо с YesApi)
     */
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

    /**
     * Получение переменной окружения с значением по умолчанию
     */
    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }

    /**
     * Включение CORS для запросов с клиентских ПК
     */
    private static void enableCORS() {
        options("/*", (request, response) -> {
            String accessControlRequestHeaders = request.headers("Access-Control-Request-Headers");
            if (accessControlRequestHeaders != null) {
                response.header("Access-Control-Allow-Headers", accessControlRequestHeaders);
            }
            String accessControlRequestMethod = request.headers("Access-Control-Request-Method");
            if (accessControlRequestMethod != null) {
                response.header("Access-Control-Allow-Methods", accessControlRequestMethod);
            }
            return "OK";
        });

        before((request, response) -> {
            response.header("Access-Control-Allow-Origin", "*");
            response.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            response.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            response.type("application/json");
        });
    }
}