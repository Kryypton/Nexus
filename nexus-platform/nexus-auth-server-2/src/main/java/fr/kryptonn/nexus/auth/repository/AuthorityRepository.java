package fr.kryptonn.nexus.auth.repository;

import fr.kryptonn.nexus.auth.entity.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority, String> {

    Optional<Authority> findByAuthority(String authority);
}
