package com.capgemini.airlinereservationsystemsecurity.beans;

import java.util.Collection;
import java.util.Date;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;
import lombok.EqualsAndHashCode.Exclude;

@Data
@Entity
@Table(name = "flight_info")
public class FlightBean {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int flightId;

	@NotNull
	@Pattern(regexp = "[a-zA-Z]*")
	@Size(min = 3, max = 25)
	@Column
	private String flightName;

	@NotNull
	@Pattern(regexp = "[a-zA-Z]*")
	@Size(min = 3, max = 20)
	@Column
	private String source;

	@NotNull
	@Size(min = 3, max = 20)
	@Column
	private String destination;

	@NotNull
	@Pattern(regexp = "[a-zA-Z]*")
	@Size(min = 3, max = 20)
	@Column
	private String classType;

	@NotNull
	@Size(min = 70, max = 300)
	@Column
	private int totalSeats;

	@NotNull
	@Size(min = 3, max = 10)
	@Column
	private double ticketPrice;


	@Column(nullable = false)
	@JsonFormat(pattern = "yyyy-MM-dd")
	private Date departureDate;

	
	@Column(nullable = false)
	@JsonFormat(pattern = "HH:mm")
	private String departureTime;
	

	@Column
	private boolean isActive;

	@Exclude
	@ManyToOne(cascade = CascadeType.ALL)
    private UserInfoBean user;
	@OneToMany(cascade = CascadeType.ALL,mappedBy = "flight")
	@JsonIgnore
	private Collection<BookingBean> booking;
}
