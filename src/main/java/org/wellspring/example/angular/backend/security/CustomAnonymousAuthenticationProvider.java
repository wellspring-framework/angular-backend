package org.wellspring.example.angular.backend.security;

import java.util.Optional;

import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.wellspring.example.angular.backend.security.old.TokenService;

public class CustomAnonymousAuthenticationProvider extends AnonymousAuthenticationProvider {
	private TokenService tokenService;

	public CustomAnonymousAuthenticationProvider(String key, TokenService tokenService) {
		super(key);
		this.tokenService = tokenService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Optional<String> token = (Optional) authentication.getPrincipal();
		if (token.isPresent() || !token.get().isEmpty()) {
			if (tokenService.contains(token.get())) {
				return null;
			}
		}
		return super.authenticate(authentication);
	}

}
