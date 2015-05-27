package org.wellspring.example.angular.backend;

import java.math.BigDecimal;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.wellspring.example.angular.backend.persistence.domain.Client;
import org.wellspring.example.angular.backend.persistence.domain.Product;
import org.wellspring.example.angular.backend.persistence.domain.User;
import org.wellspring.example.angular.backend.persistence.domain.UserRole;
import org.wellspring.example.angular.backend.persistence.repository.UserRepository;
import org.wellspring.example.angular.backend.service.ClientService;
import org.wellspring.example.angular.backend.service.ProductService;

@Configuration
public class LoadDataConfiguration {

	String[] products = { "Bike", "Camera", "Car", "pendrive", "Pencil", "Chair", "Smartphone", "Notebook", "Earphone", "Tablet", "Motocicle", "Bag", "Dress", "T-Shirt" };

	String[] clients = { "John", "Mary", "Joseph", "Paul", "Hugo", "Carl", "Melissa", "Nicole", "James", "Lucie", "Charlie", "Nathan", "Henry", "Anne", "Julie", "Isal", "Alex", "Carol", "Christine",
			"Erick", "Josie", "Raphael", "Adam", "Adele", "Barbie", "Ken", "Steve", "Roger", "Betty", "Billy", "Calvin", "Carly", "Johnson", "Cassie", "Debbie", "Deborah", "Eugene", "Everard",
			"Isabelle", "Jane", "Jason", "Fredie", "Jennifer" };

	@Resource
	private ProductService productService;

	@Resource
	private ClientService clientService;

	@Resource
	private UserRepository userRepository;

	@PostConstruct
	public void init() {
		createProducts();
		createClients();
		createUsers();
	}

	private void createProducts() {

		for (int i = 0; i < products.length; i++) {
			Product product = new Product();
			product.setName(products[i]);
			product.setPrice(generateRandomBigDecimalFromRange(BigDecimal.ZERO, BigDecimal.TEN));
			productService.save(product);
		}

	}

	private void createClients() {
		for (int i = 0; i < clients.length; i++) {
			Client client = new Client();
			client.setName(clients[i]);
			client.setEmail(client.getName().toLowerCase() + "@test.com");
			clientService.save(client);
		}
	}

	private void createUsers() {
		User admin = new User();
		admin.setUsername("admin");
		admin.setPassword(new BCryptPasswordEncoder().encode("password"));
		admin.grantRole(UserRole.ADMIN);

		User user = new User();
		user.setUsername("user");
		user.setPassword(new BCryptPasswordEncoder().encode("password"));
		user.grantRole(UserRole.USER);

		User guest = new User();
		guest.setUsername("guest");
		guest.setPassword(new BCryptPasswordEncoder().encode("password"));
		guest.grantRole(UserRole.USER);

		userRepository.save(admin);
		userRepository.save(user);
		userRepository.save(guest);
	}

	private BigDecimal generateRandomBigDecimalFromRange(BigDecimal min, BigDecimal max) {
		BigDecimal randomBigDecimal = min.add(new BigDecimal(Math.random()).multiply(max.subtract(min)));
		return randomBigDecimal.setScale(2, BigDecimal.ROUND_HALF_UP);
	}

}
