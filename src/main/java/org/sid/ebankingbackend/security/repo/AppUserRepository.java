package org.sid.ebankingbackend.security.repo;

import org.sid.ebankingbackend.security.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, String> {
    AppUser findByUsername(String name);
}
