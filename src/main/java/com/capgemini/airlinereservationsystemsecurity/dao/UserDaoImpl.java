package com.capgemini.airlinereservationsystemsecurity.dao;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.PersistenceUnit;
import javax.persistence.TypedQuery;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;

import com.capgemini.airlinereservationsystemsecurity.beans.UserInfoBean;

import lombok.extern.java.Log;

@Log
@Repository
public class UserDaoImpl implements UserDao {

	@PersistenceUnit 
	private EntityManagerFactory entityManager;
	@Autowired
	private BCryptPasswordEncoder encoder;

	@Override
	public boolean register(UserInfoBean userInfoBean) {

		EntityManager manager = entityManager.createEntityManager();
		EntityTransaction transaction = manager.getTransaction();
		transaction.begin();

		try {
			System.out.println(userInfoBean.getPassword());
	//		userInfoBean.setPassword(encoder.encode(userInfoBean.getPassword()));
			manager.persist(userInfoBean);
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
	public List<UserInfoBean> getuser(String userName) {

		EntityManager manager = entityManager.createEntityManager();
		String jpql = "select e from UserInfoBean e where e.userName=:userName";
		TypedQuery<UserInfoBean> query = manager.createQuery(jpql, UserInfoBean.class);
		query.setParameter("userName", userName);
		return query.getResultList();

	}

	@Override
	public List<UserInfoBean> getAllUsers() {

		EntityManager manager = entityManager.createEntityManager();
		String jpql = "select a from UserInfoBean a";
		TypedQuery<UserInfoBean> query = manager.createQuery(jpql, UserInfoBean.class);
		return query.getResultList();
	}

	@Override
	public boolean updateUser(UserInfoBean bean) {
		EntityManager manager = entityManager.createEntityManager();
		EntityTransaction transaction = manager.getTransaction();
		transaction.begin();

		UserInfoBean infoBean = manager.find(UserInfoBean.class, bean.getUserId());
		infoBean.setMobile(bean.getMobile());
		infoBean.setPassword(encoder.encode(bean.getPassword()));
		infoBean.setEmailId(bean.getEmailId());
		infoBean.setUserName(bean.getUserName());
		infoBean.setRole(bean.getRole());

		try {
			manager.persist(infoBean);
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
	public UserInfoBean getUser(String userName) {
		String jpql = "select u from UserInfoBean u where u.userName=:userName";
		EntityManager manager = entityManager.createEntityManager();
		TypedQuery<UserInfoBean> query = manager.createQuery(jpql, UserInfoBean.class);
		query.setParameter("userName", userName);
		return query.getSingleResult();
	}

}
