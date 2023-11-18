package org.sid.ebankingbackend.security.service;

import org.sid.ebankingbackend.security.entities.AppRole;
import org.sid.ebankingbackend.security.entities.AppUser;
import org.sid.ebankingbackend.security.repo.AppRoleRepository;
import org.sid.ebankingbackend.security.repo.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@Transactional
//@AllArgsConstructor
public class AccountServiceImpl implements AccountService {
    private AppUserRepository appUserRepository;

    private AppRoleRepository appRoleRepository;

//    private PasswordEncoder passwordEncoder;

    @Autowired
    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
//        this.passwordEncoder = passwordEncoder;
    }

    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Override
    public AppUser addNewUser(String username, String password, String email, String confirmPassword) {
        AppUser appUser = appUserRepository.findByUsername(username);
        if (appUser != null)
            throw new RuntimeException("this user already exist");
        if (!password.equals(confirmPassword))
            throw new RuntimeException("Password not match");

        appUser = AppUser.builder()
                .userId(UUID.randomUUID().toString())
                .username(username)
                .password(passwordEncoder().encode(password))
                .email(email)
                .build();
        AppUser savedAppUser = appUserRepository.save(appUser);
        return savedAppUser;
    }

    @Override
    public AppRole addNewrRole(String role) {
        AppRole appRole = appRoleRepository.findById(role).orElse(null);
        if (appRole != null) throw new RuntimeException("this role already exist");
        AppRole savedRole = appRoleRepository.save(AppRole.builder().role(role).build());
        return savedRole;
    }

    @Override
    public void addRoleToUser(String username, String role) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRepository.findById(role).get();
        appUser.getRoles().add(appRole);
//        appUserRepository.save(appUser);

    }

    @Override
    public void removeRoleFromUser(String username, String role) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRepository.findById(role).get();
        appUser.getRoles().remove(appRole);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }
}
