package org.wellspring.example.angular.backend.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.wellspring.crud.controller.impl.RestCrudControllerImpl;
import org.wellspring.example.angular.backend.persistence.domain.Client;
import org.wellspring.example.angular.backend.persistence.repository.ClientRepository;
import org.wellspring.example.angular.backend.service.ClientService;
import org.wellspring.example.angular.backend.util.ResourcePaths;

@RestController
@RequestMapping(value = ResourcePaths.Client.PRIVATE_ROOT)
public class ClientController extends RestCrudControllerImpl<ClientService, ClientRepository, Client, Long> {

}
