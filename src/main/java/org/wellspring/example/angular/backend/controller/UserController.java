package org.wellspring.example.angular.backend.controller;

import javax.annotation.Resource;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.wellspring.example.angular.backend.persistence.domain.User;
import org.wellspring.example.angular.backend.persistence.domain.UserRole;
import org.wellspring.example.angular.backend.service.UserService;
import org.wellspring.example.angular.backend.util.ResourcePaths;

@RestController
public class UserController {

	@Resource
	UserService userService;

	@RequestMapping(value = ResourcePaths.User.CURRENT, method = RequestMethod.GET)
	public User getCurrent() {

		User loggedUserDetails = null;
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (isAuthenticated(authentication)) {
			Object principal = authentication.getPrincipal();
			if (principal instanceof UserDetails) {
				loggedUserDetails = (User) ((UserDetails) principal);
			}
			else if ("anonymousUser".equals(principal)) {
				loggedUserDetails = new User(principal.toString());
				loggedUserDetails.grantRole(UserRole.ANONYMOUS);
			}
			else {
				throw new RuntimeException("Expected class of authentication principal is UserDetails. Given: " + principal.getClass());
			}
		}
		return loggedUserDetails;
	}

	private boolean isAuthenticated(Authentication authentication) {
		return authentication != null && (authentication instanceof AnonymousAuthenticationToken) && authentication.isAuthenticated();
	}

	@RequestMapping(value = ResourcePaths.User.CURRENT, method = RequestMethod.PATCH)
	public ResponseEntity<String> changePassword(@RequestBody final User user) {
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		final User currentUser = userService.findByUsername(authentication.getName());

		if (user.getNewPassword() == null || user.getNewPassword().length() < 4) {
			return new ResponseEntity<String>("new password to short", HttpStatus.UNPROCESSABLE_ENTITY);
		}

		final BCryptPasswordEncoder pwEncoder = new BCryptPasswordEncoder();
		if (!pwEncoder.matches(user.getPassword(), currentUser.getPassword())) {
			return new ResponseEntity<String>("old password mismatch", HttpStatus.UNPROCESSABLE_ENTITY);
		}

		currentUser.setPassword(pwEncoder.encode(user.getNewPassword()));
		userService.save(currentUser);
		return new ResponseEntity<String>("password changed", HttpStatus.OK);
	}

	@RequestMapping(value = "/admin/api/users/{user}/grant/role/{role}", method = RequestMethod.POST)
	public ResponseEntity<String> grantRole(@PathVariable User user, @PathVariable UserRole role) {
		if (user == null) {
			return new ResponseEntity<String>("invalid user id", HttpStatus.UNPROCESSABLE_ENTITY);
		}

		user.grantRole(role);
		userService.save(user);
		return new ResponseEntity<String>("role granted", HttpStatus.OK);
	}

	@RequestMapping(value = "/admin/api/users/{user}/revoke/role/{role}", method = RequestMethod.POST)
	public ResponseEntity<String> revokeRole(@PathVariable User user, @PathVariable UserRole role) {
		if (user == null) {
			return new ResponseEntity<String>("invalid user id", HttpStatus.UNPROCESSABLE_ENTITY);
		}

		user.revokeRole(role);
		userService.save(user);
		return new ResponseEntity<String>("role revoked", HttpStatus.OK);
	}

	@RequestMapping(value = "/admin/api/users", method = RequestMethod.GET)
	public Iterable<User> list() {
		return userService.findAll();
	}
}
