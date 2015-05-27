package org.wellspring.example.angular.backend.security.old;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TokenResponse {
	@JsonProperty
	private String token;

	public TokenResponse() {
	}

	public TokenResponse(String token) {
		this.token = token;
	}
}
