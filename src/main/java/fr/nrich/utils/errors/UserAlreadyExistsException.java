package fr.nrich.utils.errors;

/**
 * Exception when trying to create a new user with an already used username
 * 
 * @author Nils Richard
 *
 */
public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String string) {
        super(string);
    }

    /**
     * 
     */
    private static final long serialVersionUID = -6750360827094645172L;

}
