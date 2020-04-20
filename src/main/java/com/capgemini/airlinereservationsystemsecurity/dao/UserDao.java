package com.capgemini.airlinereservationsystemsecurity.dao;

import java.util.List;

import com.capgemini.airlinereservationsystemsecurity.beans.UserInfoBean;


public interface UserDao {
	
	public boolean register(UserInfoBean userInfoBean);

	public List<UserInfoBean> getuser(String userName);

	public boolean updateUser(UserInfoBean bean);

	public List<UserInfoBean> getAllUsers();
	
	public UserInfoBean getUser(String userName);
	
}
