package com.ramjava.jwt.sicherheit.leitfaden.repository;

import com.ramjava.jwt.sicherheit.leitfaden.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

    User findByUsername(String username);
}
