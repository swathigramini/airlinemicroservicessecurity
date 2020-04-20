package com.capgemini.airlinereservationsystemsecurity.service;

import java.util.List;

import com.capgemini.airlinereservationsystemsecurity.beans.UserInfoBean;



public interface UserService {
	public boolean register(UserInfoBean userInfoBean);

	public List<UserInfoBean> getuser(String userName);

	public List<UserInfoBean> getAllUsers();

	public boolean updateUser(UserInfoBean bean);
	
	public UserInfoBean getUser(String userName);
}
