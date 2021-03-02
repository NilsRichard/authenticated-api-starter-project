package fr.nrich.model.auth;

import java.util.List;

import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import fr.nrich.utils.StringListConverter;

/**
 * Simple entity to create Users for the API
 * 
 * @author Nils Richard
 *
 */
@Entity
@Table(name = APIConsumer.TABLE_NAME)
public class APIConsumer {
    public final static String TABLE_NAME = "api_consumer";

    private Long id;
    private String username;
    private String password;
    private List<String> authorities;

    /**
     * Important for JSON serialization
     */
    public APIConsumer() {
    }

    @Convert(converter = StringListConverter.class)
    public List<String> getAuthorities() {
        return authorities;
    }

    @Id
    @GeneratedValue
    public Long getId() {
        return id;
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

}
