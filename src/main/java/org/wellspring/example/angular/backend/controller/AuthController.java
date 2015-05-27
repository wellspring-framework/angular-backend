package org.wellspring.example.angular.backend.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.wellspring.example.angular.backend.util.ResourcePaths;

@RestController
@RequestMapping(value = ResourcePaths.Auth.PRIVATE_ROOT)
public class AuthController {

}
