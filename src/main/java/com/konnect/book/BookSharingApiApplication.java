package com.konnect.book;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class BookSharingApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(BookSharingApiApplication.class, args);
	}

}
