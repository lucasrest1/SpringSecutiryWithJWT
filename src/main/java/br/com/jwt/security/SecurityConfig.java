package br.com.jwt.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.com.jwt.security.services.filters.JWTAuthenticationFilter;
import br.com.jwt.security.services.filters.JWTLoginFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	protected void configure(HttpSecurity http) throws Exception {		
		http
			.csrf().disable()
			.authorizeRequests()				
				.antMatchers("/home").permitAll()
				.antMatchers(HttpMethod.POST, "/login").permitAll()
				.anyRequest().authenticated()
			.and()
			.addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
				                UsernamePasswordAuthenticationFilter.class)									
			.addFilterBefore(new JWTAuthenticationFilter(),
				                UsernamePasswordAuthenticationFilter.class);
	}
	
	
	@Override 
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication()
	 		.withUser("lucas").password("123").roles("USER")
	 		.and()
	 		.withUser("admin").password("123").roles("USER");
	}		
}
