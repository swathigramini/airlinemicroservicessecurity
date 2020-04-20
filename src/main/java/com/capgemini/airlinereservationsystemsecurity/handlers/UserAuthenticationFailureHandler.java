package com.capgemini.airlinereservationsystemsecurity.handlers;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.capgemini.airlinereservationsystemsecurity.airlineresponse.UserResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class UserAuthenticationFailureHandler implements AuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		
		UserResponse userResponse = new UserResponse();
		userResponse.setStatusCode(410);
		userResponse.setMessage("Failure");
		userResponse.setDescription("LoginFailure");
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setStatus(200);
		ObjectMapper mapper = new ObjectMapper();
		response.getWriter().write(mapper.writeValueAsString(userResponse));
		
		
	}
}
