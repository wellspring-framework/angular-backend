package org.wellspring.example.angular.backend.service.impl;

import javax.annotation.Resource;

import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.wellspring.example.angular.backend.persistence.domain.User;
import org.wellspring.example.angular.backend.persistence.repository.ReadableUserRepository;

@Service(value = "userDetailsService")
public class UserDetailsServiceImpl implements
		org.springframework.security.core.userdetails.UserDetailsService {

	@Resource
	private ReadableUserRepository readableUserRepository;

	private final AccountStatusUserDetailsChecker detailsChecker = new AccountStatusUserDetailsChecker();

	@Override
	public final User loadUserByUsername(String username)
			throws UsernameNotFoundException {
		final User user = readableUserRepository.findByUsername(username);
		if (user == null) {
			throw new UsernameNotFoundException("user not found");
		}
		detailsChecker.check(user);
		return user;
	}
}
