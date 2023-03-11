package com.example.spring.security.token;

import com.example.spring.security.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Integer> {

    List<Token> findByUserAndExpiredAndRevoked(User user, boolean expired, boolean revoked);

    Optional<Token> findByToken(String token);

}
