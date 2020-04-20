package com.capgemini.airlinereservationsystemsecurity.beans;

import java.util.Date;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;

import com.fasterxml.jackson.annotation.JsonFormat;

import lombok.Data;
import lombok.EqualsAndHashCode.Exclude;

@Data
@Entity
@Table(name = "booking_flight")
public class BookingBean {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column
	private int bookingId;

	@Column
	private int userId;

	@Column
	private int flightId;

	@Column(nullable = false)
	@JsonFormat(pattern = "yyyy-MM-dd")
	private Date journeyDate;

	@Column(nullable = false)
	@JsonFormat(pattern = "HH:mm")
	private String journeyTime;

	@Column(length = 20)
	private String source;

	@Column(length = 20)
	private String destination;

	@Min(1)
	@Max(100)
	@Column
	private int numOfSeats;

	@Exclude
	@ManyToOne(cascade = CascadeType.ALL)
	private UserInfoBean user;

	@ManyToOne(cascade = CascadeType.ALL)
	private FlightBean flight;
}