package org.example.authentication.security;

import org.example.authentication.appuser.AppUser;
import org.example.authentication.appuser.AppUserRole;
import org.example.authentication.appuser.AppUserService;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class AdminInitializer implements CommandLineRunner {

    private final AppUserService appUserService;
    private static final Logger LOGGER = org.slf4j.LoggerFactory.getLogger(AdminInitializer.class);

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.password}")
    private String adminPassword;

    public AdminInitializer(AppUserService appUserService) {
        this.appUserService = appUserService;
    }

    @Override
    public void run(String... args) {
        final AppUser admin = new AppUser("System", "Administrator", adminPassword, adminUsername, AppUserRole.ADMIN);
        appUserService.signUpUser(admin);
        appUserService.enableAppUser(adminUsername);

        LOGGER.info("Admin user initialized: username={}", adminUsername);

    }
}
