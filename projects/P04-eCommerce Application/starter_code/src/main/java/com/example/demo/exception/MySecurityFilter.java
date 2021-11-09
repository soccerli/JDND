package com.example.demo.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/***
 * Implement this bean in order to capture exceptions raised by filters (which are before any controller is being invoked),
 *and hand such exception to the exception controller.
 *
 * This filter is added in configure() of WebSecurityConfiguration, its order is also defined there at the same time
 * */

@Component
public class MySecurityFilter extends OncePerRequestFilter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Autowired
    @Qualifier("handlerExceptionResolver")
    private HandlerExceptionResolver resolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            //log.debug("inside MySecurityFilter NOW");
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("MySecurityFilter caught something, raise it to my Exception controller:", e);
            resolver.resolveException(request, response, null, e);
        }
    }
}
