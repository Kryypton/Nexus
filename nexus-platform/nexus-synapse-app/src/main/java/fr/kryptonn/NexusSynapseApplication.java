package fr.kryptonn;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static org.springframework.boot.SpringApplication.run;

@SpringBootApplication
@Slf4j
public class NexusSynapseApplication {
    public static void main(String[] args) {
        log.info("Starting Nexus Synapse Application...");
        run(NexusSynapseApplication.class, args);
        log.info("Nexus Synapse Application started successfully.");
    }
}
