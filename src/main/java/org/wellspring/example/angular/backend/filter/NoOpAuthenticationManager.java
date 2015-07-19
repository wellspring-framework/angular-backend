package org.wellspring.example.angular.backend.filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class NoOpAuthenticationManager implements AuthenticationManager {

	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		return authentication;
	}
}
