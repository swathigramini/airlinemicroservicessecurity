package com.capgemini.airlinereservationsystemsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.capgemini.airlinereservationsystemsecurity.dao.UserDao;
import com.capgemini.airlinereservationsystemsecurity.security.UserDetailsImpl;

@Component
public class UserDetailsServiceImpl implements UserDetailsService{

	@Autowired
	private UserDao dao;
	
	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		UserDetailsImpl userDetailsImpl = new UserDetailsImpl();
		userDetailsImpl.setUserInfoBean(dao.getUser(userName));
		return userDetailsImpl;
		
	}
}
