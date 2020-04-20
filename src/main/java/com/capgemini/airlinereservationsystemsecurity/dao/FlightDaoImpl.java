package com.capgemini.airlinereservationsystemsecurity.dao;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.PersistenceUnit;
import javax.persistence.TypedQuery;

import org.springframework.stereotype.Repository;

import com.capgemini.airlinereservationsystemsecurity.beans.FlightBean;

import lombok.extern.java.Log;

@Log
@Repository
public class FlightDaoImpl implements FlightDao {
	@PersistenceUnit
	private EntityManagerFactory entityManager;

	@Override
	public boolean flightRegister(FlightBean flightbean) {
		
		EntityManager manager = entityManager.createEntityManager();
		EntityTransaction transaction = manager.getTransaction();
		transaction.begin();
		
		try {
			manager.persist(flightbean);
			transaction.commit();
			return true;
		} catch (Exception e) {
			log.info(e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				log.info(element.toString());
			}
		}
		return false;
	}

	@Override
	public List<FlightBean> searchFlight(String flightName) {
		
		String jpql = "select e from FlightBean e where e.flightName=:flightName";
		EntityManager manager = entityManager.createEntityManager();
		TypedQuery<FlightBean> query = manager.createQuery(jpql, FlightBean.class);
		query.setParameter("flightName", flightName);
		return query.getResultList();
		
	}

	@Override
	public List<FlightBean> getAllFlights() {
		
		EntityManager manager = entityManager.createEntityManager();
		String jpql = "select a from FlightBean a";
		TypedQuery<FlightBean> query = manager.createQuery(jpql, FlightBean.class);
		return query.getResultList();
		
	}

	@Override
	public boolean deleteFlight(int flightId) {
		EntityManager manager = entityManager.createEntityManager();
		EntityTransaction transaction = manager.getTransaction();
		transaction.begin();
		FlightBean beans = manager.find(FlightBean.class, flightId );
		manager.remove(beans);
		transaction.commit();
		return true;
	}

	@Override
	public boolean updateFlight(FlightBean bean) {
		
		EntityManager manager = entityManager.createEntityManager();
		EntityTransaction transaction = manager.getTransaction();
		transaction.begin();
		
		FlightBean flightbean = manager.find(FlightBean.class,bean.getFlightId());
		flightbean.setFlightName(flightbean.getFlightName());
		flightbean.setSource(flightbean.getSource());
		flightbean.setDestination(flightbean.getDestination());
		flightbean.setClassType(flightbean.getClassType());
		flightbean.setTicketPrice(flightbean.getTicketPrice());
		
		try {
			manager.persist(flightbean);
			transaction.commit();
			return true;
		} catch (Exception e) {
			log.info(e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				log.info(element.toString());		}
		   return false;
	}
}
}