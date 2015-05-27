package org.wellspring.example.angular.backend.security.old;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.wellspring.example.angular.backend.filter.Http401UnauthorizedEntryPoint;
import org.wellspring.example.angular.backend.filter.TokenAuthenticationFilter;
import org.wellspring.example.angular.backend.service.impl.TokenAuthenticationService;
import org.wellspring.example.angular.backend.util.ResourcePaths;

// @Configuration
// @EnableWebMvcSecurity
// @EnableScheduling
// @EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${backend.admin.role}")
	private String backendAdminRole;

	@Resource
	UserDetailsService userDetailsService;

	@Resource
	TokenAuthenticationService tokenAuthenticationService;

	@Resource
	Http401UnauthorizedEntryPoint restAuthenticationEntryPoint;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.
				csrf().disable().
				sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).
				and().
				authorizeRequests().
				antMatchers(actuatorEndpoints()).hasRole(backendAdminRole).
				antMatchers(ResourcePaths.User.CURRENT).
				permitAll().
				antMatchers(ResourcePaths.Login.PUBLIC_ROOT).
				permitAll().
				antMatchers(ApiController.AUTHENTICATE_URL).
				permitAll().
				anyRequest().authenticated().
				and().
				anonymous().and().
				exceptionHandling().authenticationEntryPoint(restAuthenticationEntryPoint);

		http.
				addFilterBefore(new AuthenticationFilter(authenticationManager()), BasicAuthenticationFilter.class).
				addFilterBefore(new ManagementEndpointAuthenticationFilter(authenticationManager()), BasicAuthenticationFilter.class);
		// .addFilterBefore(new StatelessLoginFilter(ResourcePaths.Login.PUBLIC_ROOT, tokenAuthenticationService, userDetailsService, authenticationManager()),
		// UsernamePasswordAuthenticationFilter.class);
		// .addFilterBefore(authenticationTokenProcessingFilter(),
		// UsernamePasswordAuthenticationFilter.class);
	}

	@Bean
	public TokenAuthenticationFilter authenticationTokenProcessingFilter() {
		return new TokenAuthenticationFilter(ResourcePaths.Login.PUBLIC_ROOT);
	}

	private String[] actuatorEndpoints() {
		return new String[] { ApiController.AUTOCONFIG_ENDPOINT, ApiController.BEANS_ENDPOINT, ApiController.CONFIGPROPS_ENDPOINT,
				ApiController.ENV_ENDPOINT, ApiController.MAPPINGS_ENDPOINT,
				ApiController.METRICS_ENDPOINT, ApiController.SHUTDOWN_ENDPOINT };
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(domainUsernamePasswordAuthenticationProvider()).
				authenticationProvider(backendAdminUsernamePasswordAuthenticationProvider()).
				authenticationProvider(tokenAuthenticationProvider());
	}

	@Bean
	public TokenService tokenService() {
		return new TokenService();
	}

	@Bean
	public ExternalServiceAuthenticator someExternalServiceAuthenticator() {
		return new SomeExternalServiceAuthenticator();
	}

	@Bean
	public AuthenticationProvider domainUsernamePasswordAuthenticationProvider() {
		return new DomainUsernamePasswordAuthenticationProvider(tokenService(), someExternalServiceAuthenticator());
	}

	@Bean
	public AuthenticationProvider backendAdminUsernamePasswordAuthenticationProvider() {
		return new BackendAdminUsernamePasswordAuthenticationProvider();
	}

	@Bean
	public AuthenticationProvider tokenAuthenticationProvider() {
		return new TokenAuthenticationProvider(tokenService());
	}

}