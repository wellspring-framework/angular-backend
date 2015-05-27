package org.wellspring.example.angular.backend.service;

import org.wellspring.crud.service.CrudService;
import org.wellspring.example.angular.backend.persistence.domain.Client;
import org.wellspring.example.angular.backend.persistence.repository.ClientRepository;

public interface ClientService extends CrudService<ClientRepository, Client, Long> {

}
