package jwtg.springjwt.controller.AuthController;

import jakarta.servlet.http.HttpServletRequest;
import jwtg.springjwt.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
public class LogoutController {

    private final RedisTemplate<String, String> redisTemplate;
    private final JWTUtil jwtUtil;

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("❌ Authorization 헤더 없음");
            return ResponseEntity.badRequest().body("No token");
        }   

        String token = authHeader.substring(7).trim();
        System.out.println("🟢 추출된 토큰: " + token);

        try {
            long expiration = jwtUtil.getRemainingTime(token);
            System.out.println("⏱️ 만료 시간(ms): " + expiration);

            if (expiration <= 0) {
                System.out.println("⚠️ 이미 만료된 토큰");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token expired");
            }

            String key = "blacklist:" + token;
            redisTemplate.opsForValue().set(key, "logout", Duration.ofMillis(expiration));
            System.out.println("✅ Redis에 저장됨: " + key);

            String username = jwtUtil.getUsername(token); // username 추출
            redisTemplate.delete("refresh:" + username); // refresh 삭제

            return ResponseEntity.ok("로그아웃 성공");

        } catch (Exception e) {
            System.out.println("🚨 예외 발생: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }

}
