package com.capgemini.airlinereservationsystemsecurity.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.capgemini.airlinereservationsystemsecurity.filter.CustomUsernamePasswordAuthenticationFilter;
import com.capgemini.airlinereservationsystemsecurity.handlers.UserLogoutSuccessHandler;
import com.capgemini.airlinereservationsystemsecurity.security.AirlineManagmentSystemAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
public class AirlineManagementSystemSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private AirlineManagmentSystemAuthenticationEntryPoint  airlineAuthenticationEntryPoint;
	
	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;
	
	@Autowired
	private AuthenticationFailureHandler authenticationFailureHandler;
	
	@Autowired
	private UserLogoutSuccessHandler userLogoutSuccessHandler;
	
	@Bean
	public CustomUsernamePasswordAuthenticationFilter getCustomUsernamePasswordAuthenticationFilter() throws Exception{
		CustomUsernamePasswordAuthenticationFilter filter = new CustomUsernamePasswordAuthenticationFilter();
		filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
		filter.setAuthenticationFailureHandler(authenticationFailureHandler);
		filter.setAuthenticationManager(authenticationManager());
		return filter;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder login) throws Exception {
		login.userDetailsService(userDetailsService);
	}
	
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "DELETE", "PUT"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(Arrays.asList("*"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
	
	@Override
	protected void configure(HttpSecurity http)throws Exception {
		http.csrf().disable()
		.exceptionHandling()
		.authenticationEntryPoint(airlineAuthenticationEntryPoint)
		.and()
		.authorizeRequests()
		.anyRequest().permitAll()
		.antMatchers("/template/forgot-password","/template/change-password", "/template/getAllFlights", "/template/getFlightDetails/{flightName}","/template/register").permitAll()
		.and()
		.authorizeRequests()
		.antMatchers("/template/flightRegister").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/template/updateFlight/flightId").hasRole("ADMIN")
		.and() 
		.authorizeRequests()
		.antMatchers("/template/updateUser/userId").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/template/getAllUsers").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/template/deleteFlight/flightId").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/template/getUser").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/template/getAllFlights").hasRole("ADMIN")
		.and()
		.authorizeRequests()
		.antMatchers("/template/bookingFlights").hasRole("USER")
		.and()
		.authorizeRequests()
		.antMatchers("/template/getTicket/bookingId").hasRole("USER")
		.and()
		.authorizeRequests()
		.antMatchers("/template/deleteTicket/bookingId").hasRole("USER")
		.and()
		.addFilterBefore(getCustomUsernamePasswordAuthenticationFilter(), CustomUsernamePasswordAuthenticationFilter.class)
		.logout()
		.logoutSuccessHandler(userLogoutSuccessHandler)
		.and()
		.cors().configurationSource(corsConfigurationSource());
	}
}