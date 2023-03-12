package com.example.spring.security.config;

import com.example.spring.security.token.Token;
import com.example.spring.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        jwtToken = authHeader.substring(7);
        Token storedToken = tokenRepository.findByJwtToken(jwtToken).orElse(null);
        if (storedToken != null) {
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            storedToken.setLogOutTime(LocalDateTime.now());
            tokenRepository.save(storedToken);
        }
    }
}
