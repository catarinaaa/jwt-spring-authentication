package org.example.authentication.security.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        if(exception instanceof BadCredentialsException) {
            System.out.println("Bad credentials");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Bad credentials");
        }
        else if(exception instanceof UsernameNotFoundException) {
            System.out.println("Username not found");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Username not found");
        }
        else if(exception instanceof DisabledException) {
            System.out.println("User is disabled");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User is disabled");
        }
        else {
            System.out.println("Authentication failed");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
        }


    }
}
