package com.capgemini.airlinereservationsystemsecurity.dao;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.PersistenceUnit;
import javax.persistence.TypedQuery;

import org.springframework.stereotype.Repository;

import com.capgemini.airlinereservationsystemsecurity.beans.BookingBean;

import lombok.extern.java.Log;

@Log
@Repository
public class BookingDaoImpl implements BookingDao {

	@PersistenceUnit
	private EntityManagerFactory entityManager;

	@Override
	public boolean bookingFlights(BookingBean booking) {
		EntityManager manager = entityManager.createEntityManager();
		EntityTransaction transaction = manager.getTransaction();
		transaction.begin();

		try {
			manager.persist(booking);
			transaction.commit();
			return true;
		} catch (Exception e) {
			log.info(e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				log.info(element.toString());
			}
			return false;
		}
	}

	@Override
	public List<BookingBean> getTicket(int bookingId) {
		
		EntityManager manager = entityManager.createEntityManager();
		String jpql = "select e from BookingBean e where e.bookingId=:bookingId";
		TypedQuery<BookingBean> query = manager.createQuery(jpql, BookingBean.class);
		query.setParameter("bookingId", bookingId);
		return query.getResultList();
		
	}

	@Override
	public boolean deleteTicket(int bookingId) {
		
		EntityManager manager = entityManager.createEntityManager();
		EntityTransaction transaction = manager.getTransaction();
		transaction.begin();
		
		BookingBean beans = manager.find(BookingBean.class, bookingId );
		manager.remove(beans);
		transaction.commit();
		return true;
		
	}

}
