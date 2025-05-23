package jwtg.springjwt.controller.AuthController;

import jwtg.springjwt.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class RefreshController {

    private final JWTUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;

    @PostMapping("/token/refresh")
    public ResponseEntity<?> refreshAccessToken(@RequestHeader("Refresh-Token") String refreshToken) {

        // 1. Refresh Token 유효성 검사
        if (jwtUtil.isExpired(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh Token expired");
        }

        // 2. 사용자 정보 추출
        String username = jwtUtil.getUsername(refreshToken);
        String redisRT = redisTemplate.opsForValue().get("refresh:" + username);

        // 3. Redis에 저장된 Refresh Token과 비교
        if (redisRT == null || !redisRT.equals(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Refresh Token");
        }

        // 4. 새 Access Token 발급
        String newAccessToken = jwtUtil.createJwt(username, jwtUtil.getRole(refreshToken), 60 * 60 * 1L);

        // 5. 응답
        return ResponseEntity.ok()
                .header("Authorization", "Bearer " + newAccessToken)
                .build();
    }
}
