package fr.nrich.utils.errors;

public class InvalidJwtTokenException extends RuntimeException {

    private static final long serialVersionUID = -8921378327906366118L;

    public InvalidJwtTokenException(String message) {
        super(message);
    }

}
