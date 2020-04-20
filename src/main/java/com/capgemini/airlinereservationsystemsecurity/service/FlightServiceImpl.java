package com.capgemini.airlinereservationsystemsecurity.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.capgemini.airlinereservationsystemsecurity.beans.FlightBean;
import com.capgemini.airlinereservationsystemsecurity.dao.FlightDaoImpl;


@Service
public class FlightServiceImpl implements FlightService {

	@Autowired
	private FlightDaoImpl dao;

	@Override
	public boolean flightRegister(FlightBean flightbean) {
		return dao.flightRegister(flightbean);
	}

	@Override
	public List<FlightBean> searchFlight(String flightName) {
		return dao.searchFlight(flightName);
	}

	@Override
	public List<FlightBean> getAllFlights(){
		return dao.getAllFlights();
	}

	@Override
	public boolean deleteFlight(int flightId) {
		return dao.deleteFlight(flightId);
	}

	@Override
	public boolean updateFlight(FlightBean bean){
		return dao.updateFlight(bean);
	}
}
