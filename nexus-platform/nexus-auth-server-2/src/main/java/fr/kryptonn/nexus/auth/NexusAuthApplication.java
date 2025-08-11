package fr.kryptonn.nexus.auth;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;

import static org.springframework.boot.SpringApplication.run;

@SpringBootApplication
@Slf4j
@EnableScheduling
@ComponentScan(basePackages = {
        "fr.kryptonn.nexus.auth",                    // ✅ Votre app principale
        "fr.kryptonn.nexus.common"    // ✅ Service externe
})
public class NexusAuthApplication{

    public static void main(String[] args) {
        log.info("Starting Nexus Auth Server...");
        run(NexusAuthApplication.class, args);
        log.info("Nexus Auth Server started successfully.");
    }
}
