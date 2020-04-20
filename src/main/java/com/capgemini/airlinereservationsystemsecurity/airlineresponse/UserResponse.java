package com.capgemini.airlinereservationsystemsecurity.airlineresponse;

import java.util.List;

import com.capgemini.airlinereservationsystemsecurity.beans.UserInfoBean;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {
	private int statusCode;
	private String message;
	private String description;
	
	private UserInfoBean userInfoBean;
	private List<UserInfoBean> userList;
	
}
