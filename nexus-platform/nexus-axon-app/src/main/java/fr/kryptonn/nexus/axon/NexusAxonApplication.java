package fr.kryptonn.nexus.axon;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static org.springframework.boot.SpringApplication.run;

@SpringBootApplication
@Slf4j
public class NexusAxonApplication {
    public static void main(String[] args) {
        log.info("Starting Nexus Axon Application...");
        run(NexusAxonApplication.class, args);
        log.info("Nexus Axon Application started successfully.");
    }
}
