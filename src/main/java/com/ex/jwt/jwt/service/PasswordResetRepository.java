package com.ex.jwt.jwt.service;

import com.ex.jwt.jwt.model.PasswordReset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface PasswordResetRepository extends JpaRepository<PasswordReset, String> {
    @Query("SELECT p FROM PasswordReset p WHERE p.token = ?1 ")
    PasswordReset findByToken(String token);
}
