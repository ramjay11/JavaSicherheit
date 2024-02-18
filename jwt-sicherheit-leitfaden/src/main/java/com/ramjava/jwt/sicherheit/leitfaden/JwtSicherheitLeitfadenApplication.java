package com.ramjava.jwt.sicherheit.leitfaden;

import com.ramjava.jwt.sicherheit.leitfaden.entity.User;
import com.ramjava.jwt.sicherheit.leitfaden.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
public class JwtSicherheitLeitfadenApplication {

	@Autowired
	private UserRepository repository;

	@PostConstruct // Load at startup
	public void initUsers() {
		List<User> users = Stream.of(
				new User(100, "Huskey", "password1", "huskey@yahoo.com"),
				new User(101, "Siber", "password2", "Siber@yahoo.com"),
				new User(102, "Doray", "password3", "doray@yahoo.com"),
				new User(103, "Blackey", "password4", "blackey@yahoo.com")
		).collect(Collectors.toList());
		repository.saveAll(users);
	}
	public static void main(String[] args) {
		SpringApplication.run(JwtSicherheitLeitfadenApplication.class, args);
	}

}
