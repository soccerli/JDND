package com.example.demo.exception;

import com.auth0.jwt.exceptions.JWTVerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class SareetaAppExceptionController{
    Logger logger= LoggerFactory.getLogger(SareetaAppExceptionController.class);

    /**
     * Handle exception from UserController
     * @param e
     * @return
     */
    @ExceptionHandler(value = UserException.class)
    public ResponseEntity<Object> userException(UserException e) {
        logger.debug("UserException = \"exception with user creation\"");
        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
    }

    /**
     * Handle exceptions from OrderController
     * @param e
     * @return
     */

    @ExceptionHandler(value = OrderException.class)
    public ResponseEntity<Object> orderException(OrderException e){
        logger.debug("OrderException = \"exception with order\"");
        return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);

    }


    /**
     * Handle generic exceptions as long as they come to this exception controller and not being handled by each specific
     * exception handler
     * @param e
     * @return
     */
    @ExceptionHandler(value=Exception.class)
        public ResponseEntity<Object> handleAllException(Exception e){
        logger.debug("AllException: Generic exception, not sure what happened");
        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
    }

    /**
     * Handle exceptions raised from filters, refer to Class MySecurityFilter
     * @param e
     * @return
     */
      @ExceptionHandler(value= JWTVerificationException.class)
        public ResponseEntity<Object> handleJWTException(JWTVerificationException e){
        logger.debug("JWTVerificationException: we caught it");
        return new ResponseEntity<>(e.getMessage()+" --Caught by our Application", HttpStatus.FORBIDDEN);
    }
}
