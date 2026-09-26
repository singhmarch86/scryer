package com.example.demo;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RequestParam;

@Repository
public class JpaInjectionRepository {

    private EntityManager em;

    // Vulnerable: user-controlled sort column concatenated directly into a
    // JPQL query string (CWE-89, the JPA/Hibernate flavor). Bind parameters
    // don't help here because the injection point is in the ORDER BY
    // clause's identifier, not a value.
    public Query findAllSorted(@RequestParam String sortColumn) {
        String jpql = "SELECT p FROM Product p ORDER BY " + sortColumn;
        return em.createQuery(jpql);
    }

    // Vulnerable: same sink, source flows through a local variable one
    // statement earlier.
    public Query search(@RequestParam String name) {
        String jpql = "SELECT p FROM Product p WHERE p.name = '" + name + "'";
        Query query = em.createQuery(jpql);
        return query;
    }

    // Safe: query string is a fixed literal; the user value is bound as a
    // parameter, not concatenated.
    public Query findByNameSafe(String name) {
        Query query = em.createQuery("SELECT p FROM Product p WHERE p.name = :name");
        query.setParameter("name", name);
        return query;
    }
}
