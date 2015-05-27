package org.wellspring.example.angular.backend.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class TokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public TokenAuthenticationFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl); // defaultFilterProcessesUrl - specified in applicationContext.xml.
		super.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(defaultFilterProcessesUrl)); // Authentication will only be initiated for the request url matching this pattern
		setAuthenticationManager(new NoOpAuthenticationManager());
		setAuthenticationSuccessHandler(new TokenSimpleUrlAuthenticationSuccessHandler());
	}

	/**
	 * Attempt to authenticate request
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException,
			IOException, ServletException {

		String username = request.getHeader("X-Auth-Username");

		String token = request.getHeader("Authorization");
		logger.info("token found:" + token);

		logger.debug("[REQUEST / Body]: \n" + org.apache.commons.io.IOUtils.toString(request.getInputStream()));
		logger.debug("[REQUEST / Content-Type]: " + request.getContentType());

		AbstractAuthenticationToken userAuthenticationToken = authUserByToken(token);
		if (userAuthenticationToken == null)
			throw new AuthenticationServiceException("Invalid Token");
		return userAuthenticationToken;
	}

	/**
	 * authenticate the user based on token
	 * 
	 * @return
	 */
	private AbstractAuthenticationToken authUserByToken(String token) {

		if (token == null)
			return null;

		// TODO RESOLVER
		// String username = getUserNameFromToken(); // logic to extract username from token
		// String role = getRolesFromToken(); // extract role information from token

		// List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		// authorities.add(new SimpleGrantedAuthority(role));
		//
		// User principal = new User(username, "", authorities);
		// AbstractAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities());

		// return authToken;
		return null;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res,
			FilterChain chain) throws IOException, ServletException {
		super.doFilter(req, res, chain);
	}
}
