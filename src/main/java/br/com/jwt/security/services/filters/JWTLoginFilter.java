package br.com.jwt.security.services.filters;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.jwt.models.User;
import br.com.jwt.security.services.TokenAuthenticationService;

public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

	public JWTLoginFilter(String url, AuthenticationManager manager) {
		super(new AntPathRequestMatcher(url));
		setAuthenticationManager(manager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
		
		return getAuthenticationManager().authenticate( 
					new UsernamePasswordAuthenticationToken(
							user.getUsername(),
							user.getPassword(),
							Collections.emptyList()));
		
	}
	
	@Override
	public void successfulAuthentication(
					HttpServletRequest request,
					HttpServletResponse response,
					FilterChain chain,
					Authentication auth) throws IOException, ServletException {
		TokenAuthenticationService.addAuthentication(response, auth.getName());	
	}

}
