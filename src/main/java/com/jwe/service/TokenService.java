package com.jwe.service;

import com.jwe.exception.ApplicationException;
import com.jwe.model.TokenResponseModel;
import com.jwe.security.JwtTokenHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TokenService {


    @Autowired
    JwtTokenHelper jwtTokenHelper;

    public TokenResponseModel generateToken() throws ApplicationException {
        String token =  jwtTokenHelper.generateToken("yash");
        return new TokenResponseModel(token);
    }

}
