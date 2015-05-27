package org.wellspring.example.angular.backend.security;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UrlPathHelper;
import org.wellspring.example.angular.backend.persistence.domain.User;
import org.wellspring.example.angular.backend.security.old.AuthenticationWithToken;
import org.wellspring.example.angular.backend.security.old.TokenResponse;
import org.wellspring.example.angular.backend.util.ResourcePaths;

import com.fasterxml.jackson.databind.ObjectMapper;

public class AuthenticationFilter extends GenericFilterBean {

	private final static Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);
	public static final String TOKEN_SESSION_KEY = "token";
	public static final String USER_SESSION_KEY = "user";
	private static final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^Bearer *([^ ]+) *$", Pattern.CASE_INSENSITIVE);
	private AuthenticationManager authenticationManager;
	private org.wellspring.example.angular.backend.security.old.TokenService tokenService;

	public AuthenticationFilter(AuthenticationManager authenticationManager, org.wellspring.example.angular.backend.security.old.TokenService tokenService) {
		this.authenticationManager = authenticationManager;
		this.tokenService = tokenService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest httpRequest = asHttp(request);
		HttpServletResponse httpResponse = asHttp(response);

		Optional<String> username = null;
		Optional<String> password = null;
		Optional<String> authorization = Optional.ofNullable(httpRequest.getHeader("Authorization"));
		Optional<String> token = Optional.ofNullable(null);
		Enumeration<String> headerNames = httpRequest.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String headerName = (String) headerNames.nextElement();
			logger.debug(httpRequest.getHeader(headerName));
		}

		String resourcePath = new UrlPathHelper().getPathWithinApplication(httpRequest);

		try {
			if (postLoginAuthentication(httpRequest, resourcePath)) {
				final User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
				username = Optional.ofNullable(user.getUsername());
				password = Optional.ofNullable(user.getPassword());

				final UsernamePasswordAuthenticationToken loginToken = new UsernamePasswordAuthenticationToken(
						user.getUsername(), user.getPassword());
				processUsernamePasswordAuthentication(httpResponse, loginToken);
				return;
			}

			else if (authorization.isPresent()) {
				logger.debug("Trying to authenticate user by Bearer Token method. Authorization: {}", authorization);

				Matcher matcher = AUTHORIZATION_PATTERN.matcher(authorization.get());
				if (matcher.matches()) {
					token = Optional.ofNullable(matcher.group(1));
					logger.debug("Token: {}", token);
					if (token.isPresent()) {
						processTokenAuthentication(token);
					}
				}
			}

			logger.debug("AuthenticationFilter is passing request down the filter chain");
			addSessionContextToLogging();
			chain.doFilter(request, response);
		} catch (InternalAuthenticationServiceException internalAuthenticationServiceException) {
			SecurityContextHolder.clearContext();
			logger.error("Internal authentication service exception", internalAuthenticationServiceException);
			httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		} catch (AuthenticationException authenticationException) {
			SecurityContextHolder.clearContext();
			httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, authenticationException.getMessage());
		} finally {
			MDC.remove(TOKEN_SESSION_KEY);
			MDC.remove(USER_SESSION_KEY);
		}

	}

	private void processUsernamePasswordAuthentication(HttpServletResponse httpResponse, UsernamePasswordAuthenticationToken loginToken) throws IOException {
		Authentication responseAuthentication = authenticate(loginToken);

		if (responseAuthentication == null || !responseAuthentication.isAuthenticated()) {
			throw new InternalAuthenticationServiceException("Unable to authenticate Domain User for provided credentials");
		}
		SecurityContextHolder.getContext().setAuthentication(responseAuthentication);

		httpResponse.setStatus(HttpServletResponse.SC_OK);
		TokenResponse tokenResponse = new TokenResponse(responseAuthentication.getDetails().toString());
		String tokenJsonResponse = new ObjectMapper().writeValueAsString(tokenResponse);
		httpResponse.addHeader("Content-Type", "application/json");
		httpResponse.getWriter().print(tokenJsonResponse);
		logger.debug("User successfully authenticated");

	}

	public Authentication authenticate(Authentication loginToken) throws AuthenticationException {
		Optional<Object> username = Optional.ofNullable(loginToken.getPrincipal());
		Optional<Object> password = Optional.ofNullable(loginToken.getCredentials());

		if (!username.isPresent() || !password.isPresent()) {
			throw new BadCredentialsException("Invalid Domain User Credentials");
		}
		Authentication authentication = authenticationManager.authenticate(loginToken);
		org.wellspring.example.angular.backend.security.old.AuthenticationWithToken resultOfAuthentication = new AuthenticationWithToken(authentication.getPrincipal(),
				authentication.getCredentials(), authentication.getAuthorities());
		String newToken = tokenService.generateNewToken();
		resultOfAuthentication.setToken(newToken);
		tokenService.store(newToken, resultOfAuthentication);

		return resultOfAuthentication;
	}

	private boolean postLoginAuthentication(HttpServletRequest httpRequest, String resourcePath) {
		return ResourcePaths.Login.PUBLIC_ROOT.equalsIgnoreCase(resourcePath) && httpRequest.getMethod().equals("POST");
	}

	private HttpServletRequest asHttp(ServletRequest request) {
		return (HttpServletRequest) request;
	}

	private HttpServletResponse asHttp(ServletResponse response) {
		return (HttpServletResponse) response;
	}

	private void addSessionContextToLogging() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String tokenValue = "EMPTY";
		if (authentication != null && !StringUtils.isEmpty(authentication.getDetails().toString())) {
			MessageDigestPasswordEncoder encoder = new MessageDigestPasswordEncoder("SHA-1");
			tokenValue = encoder.encodePassword(authentication.getDetails().toString(), "not_so_random_salt");
		}
		MDC.put(TOKEN_SESSION_KEY, tokenValue);

		String userValue = "EMPTY";
		if (authentication != null && !StringUtils.isEmpty(authentication.getPrincipal().toString())) {
			userValue = authentication.getPrincipal().toString();
		}
		MDC.put(USER_SESSION_KEY, userValue);
	}

	private void processTokenAuthentication(Optional<String> token) {
		Authentication resultOfAuthentication = tryToAuthenticateWithToken(token);
		SecurityContextHolder.getContext().setAuthentication(resultOfAuthentication);
	}

	private Authentication tryToAuthenticateWithToken(Optional<String> token) {
		PreAuthenticatedAuthenticationToken requestAuthentication = new PreAuthenticatedAuthenticationToken(token, null);
		return tryToAuthenticate(requestAuthentication);
	}

	private Authentication tryToAuthenticate(Authentication requestAuthentication) {
		Authentication responseAuthentication = authenticationManager.authenticate(requestAuthentication);
		if (responseAuthentication == null || !responseAuthentication.isAuthenticated()) {
			throw new InternalAuthenticationServiceException("Unable to authenticate Domain User for provided credentials");
		}
		logger.debug("User successfully authenticated");
		return responseAuthentication;
	}

}
