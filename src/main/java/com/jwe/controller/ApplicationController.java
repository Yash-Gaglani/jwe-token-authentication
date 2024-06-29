package com.jwe.controller;

import com.jwe.exception.ApplicationException;
import com.jwe.model.TokenResponseModel;
import com.jwe.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApplicationController {

    @Autowired
    TokenService tokenService;

    @GetMapping()
    public String greet(){
        return "Hello World";
    }

    @GetMapping("/token")
    public TokenResponseModel getToken() throws ApplicationException {
        return tokenService.generateToken();
    }
}
