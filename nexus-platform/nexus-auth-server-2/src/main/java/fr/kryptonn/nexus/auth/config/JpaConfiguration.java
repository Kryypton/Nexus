package fr.kryptonn.nexus.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;

import jakarta.persistence.EntityManagerFactory;

/**
 * ✅ Configuration JPA pour résoudre les problèmes de transactions et requêtes nommées
 */
@Configuration
@EnableJpaRepositories(
        basePackages = "fr.kryptonn.nexus.auth.repository",
        enableDefaultTransactions = true
)
@EnableTransactionManagement
public class JpaConfiguration {

    /**
     * ✅ Configuration explicite du gestionnaire de transactions
     */
    @Bean
    public PlatformTransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
        JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(entityManagerFactory);
        return transactionManager;
    }
}