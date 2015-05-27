package org.wellspring.example.angular.backend.persistence.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.wellspring.crud.persistence.repository.CrudRepository;
import org.wellspring.example.angular.backend.persistence.domain.Client;

public interface ClientRepository extends CrudRepository<Client, Long> {

	@Query(value = "select entity from Client entity where upper(e.name) like %upper(:searchTerm%)")
	Page<Client> fullTextSearch(@Param("searchTerm") String searchTerm, Pageable pageable);

}