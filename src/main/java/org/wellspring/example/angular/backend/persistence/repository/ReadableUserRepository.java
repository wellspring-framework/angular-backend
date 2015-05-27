package org.wellspring.example.angular.backend.persistence.repository;

import org.wellspring.crud.persistence.repository.ReadableRepository;
import org.wellspring.example.angular.backend.persistence.domain.User;

public interface ReadableUserRepository extends ReadableRepository<User, Long> {

	public User findByUsername(String username);

}