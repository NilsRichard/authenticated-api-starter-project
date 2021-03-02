package fr.nrich.dao;

import java.math.BigInteger;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import fr.nrich.model.auth.APIConsumer;

@Repository
public interface APIConsumerDAO extends JpaRepository<APIConsumer, Long> {
    @Query(value = "SELECT * FROM " + APIConsumer.TABLE_NAME + " u WHERE u.username = :username", nativeQuery = true)
    public APIConsumer getUserByName(@Param("username") String username);

    @Query(value = "SELECT COUNT(*) FROM " + APIConsumer.TABLE_NAME
            + " u WHERE u.username = :username", nativeQuery = true)
    public BigInteger countUserByName(@Param("username") String username);

    public default boolean checkForExistanceUsername(String username) {
        return countUserByName(username).compareTo(BigInteger.ZERO) > 0;
    }
}
