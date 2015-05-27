package org.wellspring.example.angular.backend.security.old;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

public class AuthenticatedExternalWebService extends AuthenticationWithToken {

	private ExternalWebServiceStub externalWebService;

	public AuthenticatedExternalWebService(Object aPrincipal, Object aCredentials, Collection<? extends GrantedAuthority> anAuthorities) {
		super(aPrincipal, aCredentials, anAuthorities);
	}

	public void setExternalWebService(ExternalWebServiceStub externalWebService) {
		this.externalWebService = externalWebService;
	}

	public ExternalWebServiceStub getExternalWebService() {
		return externalWebService;
	}
}
