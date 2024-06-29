package com.jwe.security;

import com.jwe.exception.ApplicationException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.text.ParseException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String BEARER = "Bearer";
    public static final String AUTHORIZATION = "Authorization";

    JwtTokenHelper jwtTokenHelper;

    public JwtAuthenticationFilter(
        JwtTokenHelper jwtTokenHelper) {
        this.jwtTokenHelper = jwtTokenHelper;
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request,
        @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
        throws ServletException, IOException {
        try {
            logRequest(request);
            doInternalAuthentication(request);
            filterChain.doFilter(request, response);
        } catch (BadJOSEException | ApplicationException | ParseException | JOSEException e) {
            log.error("JwtAuthenticationFilter:doFilterInternal::", e);
            throw new RuntimeException(e);
        }
    }

    private static void logRequest(HttpServletRequest request) {
        log.info("REQUEST_METHOD::{}:{}", request.getMethod(), request.getRequestURI());
        Enumeration<String> headerNames = request.getHeaderNames();
        Map<String, String> headers = new HashMap<>();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
        }
        log.info("REQUEST_HEADERS::{}", headers);
    }


    private void doInternalAuthentication(HttpServletRequest request)
        throws ApplicationException, BadJOSEException, ParseException, JOSEException {

        final String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER)) {
            log.warn("Authorization Header empty or does not begin with bearer");
        } else if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = authorizationHeader.substring(7);

            if (jwtTokenHelper.validateToken(token)) {
                TokenBasedAuthentication tokenBasedAuthentication = new TokenBasedAuthentication(
                    null, Collections.emptyList());

                // Set the token and authentication details
                tokenBasedAuthentication.setToken(token);
                tokenBasedAuthentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication object in the security context
                SecurityContextHolder.getContext().setAuthentication(tokenBasedAuthentication);
            }
        }
    }

}
