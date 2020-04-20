package com.capgemini.airlinereservationsystemsecurity.beans;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Data;

@Data
@Entity
@Table(name = "ticket_booking_details")
public class TicketBean {

	@Id
	@Column
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int ticketId;

	@Column
	private double price;

	@Column
	private int no_of_seats;

	@Column
	private int flightId;

	@Column
	private int userId;

	@Column(length = 20)
	private String source;

	@Column(length = 20)
	private String destination;	
}
