package com.capgemini.airlinereservationsystemsecurity.airlineresponse;

import java.util.List;

import com.capgemini.airlinereservationsystemsecurity.beans.FlightBean;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FlightResponse {

	private int statusCode;
	private String message;
	private String description;
	
	private FlightBean flightBean;
	private List<FlightBean> flightList;	
}
