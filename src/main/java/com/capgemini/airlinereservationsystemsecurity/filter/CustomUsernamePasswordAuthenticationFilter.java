package com.capgemini.airlinereservationsystemsecurity.filter;

import java.io.BufferedReader;
import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.MediaType;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.capgemini.airlinereservationsystemsecurity.beans.UserInfoBean;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CustomUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	@Override
	public String obtainPassword(HttpServletRequest request) {
		if (request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE)) {
			try {
				UserInfoBean userInfoBean = getUserInfo(request);
				return userInfoBean.getPassword();
			} catch (IOException e) {
				e.printStackTrace();
				return "";
			}
		}
		return super.obtainPassword(request);
	}

	@Override
	protected String obtainUsername(HttpServletRequest request) {
		if (request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE)) {
			try {
				UserInfoBean infoBean = getUserInfo(request);
				return infoBean.getUserName();
			} catch (IOException e) {
				e.printStackTrace();
				return "";
			}
		}
		return super.obtainUsername(request);
	}

	private UserInfoBean getUserInfo(HttpServletRequest request) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		String json = "";
		BufferedReader reader = request.getReader();
		while (reader.ready()) {
			json = json + reader.readLine();
		}
		System.out.println(json);
		UserInfoBean userBean = mapper.readValue(json, UserInfoBean.class);
		reader.reset();
		return userBean;
	}
}
