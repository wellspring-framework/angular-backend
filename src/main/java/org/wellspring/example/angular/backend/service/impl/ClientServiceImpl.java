package org.wellspring.example.angular.backend.service.impl;

import org.springframework.stereotype.Service;
import org.wellspring.crud.service.impl.CrudServiceImpl;
import org.wellspring.example.angular.backend.persistence.domain.Client;
import org.wellspring.example.angular.backend.persistence.repository.ClientRepository;
import org.wellspring.example.angular.backend.service.ClientService;

@Service
public class ClientServiceImpl extends
		CrudServiceImpl<ClientRepository, Client, Long> implements ClientService {

}
