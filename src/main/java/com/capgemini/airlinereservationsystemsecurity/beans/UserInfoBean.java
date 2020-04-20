package com.capgemini.airlinereservationsystemsecurity.beans;

import java.util.Collection;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;
import lombok.EqualsAndHashCode.Exclude;

@Data
@Entity
@Table(name = "user_info")
public class UserInfoBean {

	@Id
	@Column
	@GeneratedValue
	private int userId;

	@NotNull
	@Column
	@Pattern(regexp = "[a-zA-Z]*")
	@Size(min = 3, max = 20)
	private String userName;
	
	@NotNull
	@Column(unique = true)
	@Pattern(regexp = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$")
	private String emailId;
	
	@NotNull
	@Column
	@Pattern(regexp = "^(?=.[A-Za-z])(?=.\\d)(?=.[@$!%#?&])[A-Za-z\\d@$!%*#?&]{8,}$")
	@Size(min = 8, max = 20)
	private String password;
	
	@NotNull
	@Column
	@Pattern(regexp = "[a-zA-Z]*")
	private String role;

	@NotNull
	@Column
	@Pattern(regexp = "[a-zA-Z]*")
	@Size(min = 3, max = 30)
	private String nationality;
	
	@NotNull
	@Column
	@Pattern(regexp = "[a-zA-Z]*")
	@Size(min = 3, max = 100)
	private String address;
	
	@NotNull
	@Column(length = 10)
	private long mobile;

	@Exclude
    @OneToMany(cascade = CascadeType.ALL,mappedBy = "user")
	@JsonIgnore
	private Collection<BookingBean> booking;
	@OneToMany(cascade = CascadeType.ALL,mappedBy = "user")
	@JsonIgnore
	private Collection<FlightBean> flight;
}