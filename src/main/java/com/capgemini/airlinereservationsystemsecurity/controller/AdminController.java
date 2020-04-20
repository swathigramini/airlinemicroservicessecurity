package com.capgemini.airlinereservationsystemsecurity.controller;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.capgemini.airlinereservationsystemsecurity.airlineresponse.FlightResponse;
import com.capgemini.airlinereservationsystemsecurity.airlineresponse.UserResponse;
import com.capgemini.airlinereservationsystemsecurity.beans.FlightBean;
import com.capgemini.airlinereservationsystemsecurity.beans.UserInfoBean;

@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", allowCredentials = "true", exposedHeaders = "Access-Control-Allow-Origin")//origins = "*")
public class AdminController {
	@Autowired
	private RestTemplate restTemplate;


	@RequestMapping(value = "/template/getAllFlights")
	public FlightResponse getAllFlights() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<String> entity = new HttpEntity<String>(headers);

		return restTemplate
				.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/getAllFlights", HttpMethod.GET, entity, FlightResponse.class)
				.getBody();
	}

	@RequestMapping(value = "/template/getFlightDetails/flightName")
	public FlightResponse getFlightList(@PathVariable("flightName") String flightName) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<String> entity = new HttpEntity<String>(headers);

		return restTemplate
				.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/getFlightDetails/ "+ flightName, HttpMethod.GET, entity, FlightResponse.class)
				.getBody();
	}

	@RequestMapping(value = "/template/getUser/{userName}")
	public UserResponse getUser(@PathVariable("userName") String userName) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<UserResponse> entity = new HttpEntity<UserResponse>(headers);

		return restTemplate
			    .exchange("http://airlinesystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/getUser/" +userName, HttpMethod.GET, entity, UserResponse.class)
				.getBody();
	}

	@RequestMapping(value = "/template/getAllUsers")
	public UserResponse getAllUsers() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<UserResponse> entity = new HttpEntity<UserResponse>(headers);

		return restTemplate
				.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/getAllUsers", HttpMethod.GET, entity, UserResponse.class)
				.getBody();
	}

	@RequestMapping(value = "/template/register", method = RequestMethod.POST)
	public UserResponse userRegister(@RequestBody UserInfoBean userInfoBean) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<UserInfoBean> entity = new HttpEntity<UserInfoBean>(userInfoBean, headers);

		return restTemplate.exchange("http://airlinesystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/register", HttpMethod.POST, entity, UserResponse.class)
				.getBody();
	}

	
	@RequestMapping(value = "/template/flightRegister", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	public FlightResponse addFlight(@RequestBody FlightBean flightBean) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<FlightBean> entity = new HttpEntity<FlightBean>(flightBean, headers);

		return restTemplate.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/flightRegister", HttpMethod.POST, entity,FlightResponse.class)
				.getBody();
	}


	@RequestMapping(value = "/template/updateUser/userId", method = RequestMethod.PUT)
	public UserResponse updateUser(@PathVariable("userId") String userId, @RequestBody UserInfoBean userInfoBean) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<UserInfoBean> entity = new HttpEntity<UserInfoBean>(userInfoBean, headers);

		return restTemplate
				.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/updateUser/" + userId, HttpMethod.PUT, entity, UserResponse.class)
				.getBody();
	}

	
	@RequestMapping(value = "/template/updateFlight/flightId", method = RequestMethod.PUT)
	public FlightResponse updateFlight(@PathVariable("flightId") String flightId, @RequestBody FlightBean flightBean) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<FlightBean> entity = new HttpEntity<FlightBean>(flightBean, headers);

		return restTemplate.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/updateFlight/" + flightId, HttpMethod.PUT, entity,
				FlightResponse.class).getBody();
	}

	@RequestMapping(value = "/template/deleteFlight/flightId", method = RequestMethod.DELETE)
	public FlightResponse deleteFlight(@PathVariable("flightId") String flightId) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<FlightResponse> entity = new HttpEntity<FlightResponse>(headers);

		return restTemplate.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8083/deleteFlight/" + flightId, HttpMethod.DELETE, entity,
				FlightResponse.class).getBody();
	}
}