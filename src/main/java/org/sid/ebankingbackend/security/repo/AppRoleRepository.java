package org.sid.ebankingbackend.security.repo;

import org.sid.ebankingbackend.security.entities.AppRole;
import org.sid.ebankingbackend.security.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole, String> {
 }
