package org.wellspring.example.angular.backend.filter;

import java.io.IOException;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import org.wellspring.example.angular.backend.service.impl.TokenAuthenticationService;

// @Component
public class StatelessAuthenticationFilter extends GenericFilterBean {

	@Resource
	private TokenAuthenticationService tokenAuthenticationService;

	@Override
	public void doFilter(ServletRequest req, ServletResponse res,
			FilterChain chain) throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(
				tokenAuthenticationService
						.getAuthentication((HttpServletRequest) req));
		chain.doFilter(req, res); // always continue
	}

	@Override
	public void destroy() {
	}
}