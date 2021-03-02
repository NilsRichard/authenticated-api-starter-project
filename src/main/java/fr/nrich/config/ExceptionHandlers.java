package fr.nrich.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import fr.nrich.utils.errors.InvalidAuthorizationHeaderException;
import fr.nrich.utils.errors.InvalidJwtTokenException;
import fr.nrich.utils.errors.UserAlreadyExistsException;
import javassist.tools.web.BadHttpRequest;

@ControllerAdvice
public class ExceptionHandlers {

    Logger logger = LogManager.getLogger(getClass());

    class DetailedExceptionResponse extends ExceptionResponse {

        private String detail;

        public DetailedExceptionResponse(String detail, String error, Long timestamp) {
            super(error, timestamp);
            this.detail = detail;
        }

        public String getDetail() {
            return detail;
        }

        public void setDetail(String detail) {
            this.detail = detail;
        }

    }

    class ExceptionResponse {
        private String error;

        private Long timestamp;

        public ExceptionResponse(String error, Long timestamp) {
            super();
            this.error = error;
            this.timestamp = timestamp;
        }

        public String getError() {
            return error;
        }

        public Long getTimestamp() {
            return timestamp;
        }

        public void setError(String message) {
            this.error = message;
        }

        public void setTimestamp(Long timestamp) {
            this.timestamp = timestamp;
        }

    }

    @ExceptionHandler(value = { AccessDeniedException.class })
    public ResponseEntity<ExceptionResponse> handleInvalidInputException(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response(ex.getMessage()));
    }

    @ExceptionHandler(value = { AuthenticationException.class })
    public ResponseEntity<ExceptionResponse> handleInvalidInputException(AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response(ex.getMessage()));
    }

    @ExceptionHandler(value = { BadHttpRequest.class })
    public ResponseEntity<ExceptionResponse> handleInvalidInputException(BadHttpRequest ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response("BAD_REQUEST"));
    }

    @ExceptionHandler(value = { InvalidAuthorizationHeaderException.class })
    public ResponseEntity<ExceptionResponse> handleInvalidInputException(InvalidAuthorizationHeaderException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response("INVALID_AUTHENTICATION_HEADER"));
    }

    @ExceptionHandler(value = { InvalidJwtTokenException.class })
    public ResponseEntity<ExceptionResponse> handleInvalidInputException(InvalidJwtTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response("INVALID_JWT_TOKEN", ex.getMessage()));
    }

    @ExceptionHandler(value = { UserAlreadyExistsException.class })
    public ResponseEntity<ExceptionResponse> handleInvalidInputException(UserAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response("ALREADY_USED_USERNAME"));
    }

    private ExceptionResponse response(String msg) {
        return new ExceptionResponse(msg, System.currentTimeMillis());
    }

    private ExceptionResponse response(String msg, String detail) {
        return new DetailedExceptionResponse(detail, msg, System.currentTimeMillis());
    }
}