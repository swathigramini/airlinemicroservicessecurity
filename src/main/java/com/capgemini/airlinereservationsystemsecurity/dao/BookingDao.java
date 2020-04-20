package com.capgemini.airlinereservationsystemsecurity.dao;

import java.util.List;

import com.capgemini.airlinereservationsystemsecurity.beans.BookingBean;


public interface BookingDao {

	public boolean bookingFlights(BookingBean booking);
	
	public List<BookingBean> getTicket(int bookingId);
	
	public boolean deleteTicket(int bookingId);
	
}
