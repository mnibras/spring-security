package com.example.spring.security.auth;

import com.example.spring.security.config.JwtService;
import com.example.spring.security.token.Token;
import com.example.spring.security.token.TokenRepository;
import com.example.spring.security.token.TokenType;
import com.example.spring.security.user.Role;
import com.example.spring.security.user.User;
import com.example.spring.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest registerRequest) {
        User user = User.builder()
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                .username(registerRequest.getUsername())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();
        User savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        saveUserToken(savedUser, jwtToken);
        log.info("New user registered successfully. username: {}", registerRequest.getUsername());
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthResponse authenticate(AuthRequest authRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        User user = userRepository.findByUsername(authRequest.getUsername()).orElseThrow();
        String jwtToken = jwtService.generateToken(user);
        deleteAllExistingTokens(user);
        saveUserToken(user, jwtToken);
        log.info("User authenticated successfully. username: {}", authRequest.getUsername());
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }

    private void deleteAllExistingTokens(User user) {
        List<Token> existingTokensForUser = tokenRepository.findByUser(user);
        if (!existingTokensForUser.isEmpty()) {
            tokenRepository.deleteAll(existingTokensForUser);
        }
    }

    private void saveUserToken(User savedUser, String jwtToken) {
        Token token = Token.builder()
                .jwtToken(jwtToken)
                .tokenType(TokenType.BEARER)
                .user(savedUser)
                .expired(false)
                .revoked(false)
                .logInTime(LocalDateTime.now())
                .build();
        tokenRepository.save(token);
    }
}
