package org.wellspring.example.angular.backend.security.old;

public interface ExternalServiceAuthenticator {

	AuthenticationWithToken authenticate(String username, String password);
}
