package com.capgemini.airlinereservationsystemsecurity.airlineresponse;

import java.util.List;

import com.capgemini.airlinereservationsystemsecurity.dao.BookingDao;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TicketResponse {

	private int statusCode;
	private String message;
	private String description;
	
	private BookingDao ticketbean;
	private List<BookingDao> ticketList;
}
