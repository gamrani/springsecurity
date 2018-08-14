package com.auth.authspringsecurity.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.auth.autspringsecurity.users.User;
import com.auth0.jwt.JWT;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static com.auth.authspringsecurity.security.SecurityConstants.EXPIRATION_TIME;
import static com.auth.authspringsecurity.security.SecurityConstants.HEADER_STRING;
import static com.auth.authspringsecurity.security.SecurityConstants.SECRET;
import static com.auth.authspringsecurity.security.SecurityConstants.TOKEN_PREFIX;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	@Autowired
	private AuthenticationManager authenticationManager;

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		
		try {
			  // Get our user from the request (JSON), we use objectMapper to deserialize JSON to Java OBject 
			  User user = new ObjectMapper().readValue(request.getInputStream(),User.class);
			  
			  return authenticationManager.authenticate(
					  new UsernamePasswordAuthenticationToken(
							  user.getUsername(),
							  user.getPassoword(),
							  new ArrayList<>())
					  );
			
		}catch(IOException e) {
			return (Authentication) new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, 
			HttpServletResponse response,
			FilterChain chain,
			Authentication authResult) throws IOException, ServletException 
	{
		String token = JWT.create()
                .withSubject(((User) authResult.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.getBytes()));
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
	}
	
	
	
}
