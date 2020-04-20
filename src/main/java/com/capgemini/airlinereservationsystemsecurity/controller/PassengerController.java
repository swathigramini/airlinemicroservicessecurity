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

import com.capgemini.airlinereservationsystemsecurity.airlineresponse.BookingResponse;
import com.capgemini.airlinereservationsystemsecurity.beans.BookingBean;

@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", allowCredentials = "true", exposedHeaders = "Access-Control-Allow-Origin")
public class PassengerController {
	@Autowired
	private RestTemplate restTemplate;

	@RequestMapping(value = "/template/bookingFlights", method = RequestMethod.POST)
	public BookingResponse bookingFlight(@RequestBody BookingBean bookingBean) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<BookingBean> entity = new HttpEntity<BookingBean>(bookingBean, headers);

		return restTemplate
				.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8084/bookingFlights", HttpMethod.POST, entity, BookingResponse.class)
				.getBody();
	}

	@RequestMapping(value = "/template/getTicket/bookingId")
	public BookingResponse getTicket() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<BookingResponse> entity = new HttpEntity<BookingResponse>(headers);

		return restTemplate.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8084/getTicket/bookingId", HttpMethod.GET, entity, BookingResponse.class)
				.getBody();
	}

	@RequestMapping(value = "/template/deleteTicket/bookingId", method = RequestMethod.DELETE)
	public BookingResponse deleteTicket(@PathVariable("bookingId") String bookingId) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		HttpEntity<BookingResponse> entity = new HttpEntity<BookingResponse>(headers);

		return restTemplate.exchange("http://airlinessystem.c7uqfmf4vukb.ap-south-1.rds.amazonaws.com:8084/deleteTicket/{bookingId}" + bookingId, HttpMethod.DELETE, entity,
				BookingResponse.class).getBody();
	}

}
