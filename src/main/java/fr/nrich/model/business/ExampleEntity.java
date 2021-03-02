package fr.nrich.model.business;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
/**
 * This is an example of an entity that is going to persist in the database
 * 
 * @author Nils Richard
 *
 */
@Entity
@Table(name = ExampleEntity.TABLE_NAME)
public class ExampleEntity {
    public final static String TABLE_NAME = "exemple";

    private Long id;
    private String exempleField;

    /**
     * Important for JSON serialization
     */
    public ExampleEntity() {
    }

    @Id
    @GeneratedValue
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getExempleField() {
        return exempleField;
    }

    public void setExempleField(String exempleField) {
        this.exempleField = exempleField;
    }

}
