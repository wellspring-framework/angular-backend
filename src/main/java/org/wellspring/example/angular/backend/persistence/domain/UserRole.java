package org.wellspring.example.angular.backend.persistence.domain;

public enum UserRole {
	USER, ADMIN, ANONYMOUS;

	public UserAuthority asAuthorityFor(final User user) {
		final UserAuthority authority = new UserAuthority();
		authority.setAuthority("ROLE_" + toString());
		authority.setUser(user);
		return authority;
	}

	public static UserRole valueOf(final UserAuthority authority) {
		switch (authority.getAuthority()) {
		case "ROLE_USER":
			return USER;
		case "ROLE_ADMIN":
			return ADMIN;
		case "ROLE_ANONYMOUS":
			return ANONYMOUS;
		}
		throw new IllegalArgumentException("No role defined for authority: "
				+ authority.getAuthority());
	}
}