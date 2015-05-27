package org.wellspring.example.angular.backend.security;

import javax.annotation.Resource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.wellspring.example.angular.backend.filter.Http401UnauthorizedEntryPoint;
import org.wellspring.example.angular.backend.filter.StatelessAuthenticationFilter;
import org.wellspring.example.angular.backend.handler.NoRedirectLogoutSuccessHandler;
import org.wellspring.example.angular.backend.security.old.DomainUsernamePasswordAuthenticationProvider;
import org.wellspring.example.angular.backend.security.old.ExternalServiceAuthenticator;
import org.wellspring.example.angular.backend.security.old.SomeExternalServiceAuthenticator;
import org.wellspring.example.angular.backend.security.old.TokenAuthenticationProvider;
import org.wellspring.example.angular.backend.security.old.TokenService;
import org.wellspring.example.angular.backend.service.impl.TokenAuthenticationService;

@Configuration
@EnableWebMvcSecurity
@EnableScheduling
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	public static final String ANONYMOUS_TOKEN = "anonymous";

	@Resource
	Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint;

	@Resource
	TokenAuthenticationService tokenAuthenticationService;

	@Resource
	UserDetailsService userDetailsService;

	//
	// @Override
	// protected void configure(HttpSecurity http) throws Exception {
	// http.
	// csrf().disable().
	// sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).
	// and().
	// authorizeRequests().
	// antMatchers(ResourcePaths.User.CURRENT).
	// permitAll().
	// antMatchers(ResourcePaths.Login.PUBLIC_ROOT).
	// permitAll().
	// antMatchers(HttpMethod.GET,ResourcePaths.PUBLIC_ROOT_API + "/**").
	// permitAll().
	// antMatchers(HttpMethod.GET,ResourcePaths.PRIVATE_ROOT_API + "/**").authenticated().
	// antMatchers(HttpMethod.POST, ResourcePaths.PRIVATE_ROOT_API + "/**").hasRole("ADMIN").
	// antMatchers(HttpMethod.PUT, ResourcePaths.PRIVATE_ROOT_API + "/**").hasRole("ADMIN").
	// antMatchers(HttpMethod.DELETE, ResourcePaths.PRIVATE_ROOT_API + "/**").hasRole("ADMIN").
	// anyRequest().authenticated().
	// and().
	// anonymous().and().
	// logout().logoutSuccessHandler(logoutSuccessHandler()).
	// logoutUrl(ResourcePaths.Logout.PUBLIC_ROOT).and().
	// exceptionHandling().authenticationEntryPoint(http401UnauthorizedEntryPoint);
	//
	// http.addFilterBefore(new org.wellspring.example.angular.backend.security.AuthenticationFilter(authenticationManager(), tokenService()), BasicAuthenticationFilter.class);
	// http.addFilterBefore(anonymousAuthenticationFilter(), BasicAuthenticationFilter.class);
	// }
	//

	// TODO REMOVE AFTER
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.csrf().disable()
				.anonymous().and()
				.authorizeRequests().anyRequest().permitAll();
		// http.addFilterBefore(new org.wellspring.example.angular.backend.security.AuthenticationFilter(authenticationManager(), tokenService()), BasicAuthenticationFilter.class);
		http.addFilterBefore(anonymousAuthenticationFilter(), BasicAuthenticationFilter.class);
	}

	@Bean
	public LogoutSuccessHandler logoutSuccessHandler() {
		return new NoRedirectLogoutSuccessHandler();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
		auth.authenticationProvider(tokenAuthenticationProvider());
		// auth.authenticationProvider(anonymousAuthenticationProvider());

	}

	@Bean
	public StatelessAuthenticationFilter statelessAuthenticationFilter() {
		return new StatelessAuthenticationFilter();
	}

	@Bean
	public AuthenticationProvider domainUsernamePasswordAuthenticationProvider() {
		return new DomainUsernamePasswordAuthenticationProvider(tokenService(), someExternalServiceAuthenticator());
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
	public AuthenticationProvider tokenAuthenticationProvider() {
		return new TokenAuthenticationProvider(tokenService());
	}

	@Bean
	public AnonymousAuthenticationProvider anonymousAuthenticationProvider() {
		return new CustomAnonymousAuthenticationProvider(ANONYMOUS_TOKEN, tokenService());
	}

	/**
	 * If there is no authentication it will populate the security context with
	 * 'ROLE_ANONYMOUS', using the AnonymousAuthenticationToken, the token is
	 * the key.
	 *
	 * @return
	 */
	@Bean
	public AnonymousAuthenticationFilter anonymousAuthenticationFilter() {

		AnonymousAuthenticationFilter f = new AnonymousAuthenticationFilter(ANONYMOUS_TOKEN);
		return f;
	}

}
