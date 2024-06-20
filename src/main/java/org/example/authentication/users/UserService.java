package org.example.authentication.users;

import org.example.authentication.appuser.AppUser;
import org.example.authentication.appuser.UserRepository;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private UserRepository userRepository;
    private static final Logger LOGGER = org.slf4j.LoggerFactory.getLogger(UserService.class);

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<UserProfile> getUsers() {
        return userRepository.findAll().stream().map(UserProfileMapper::map).toList();
    }

    public UserProfile getLoggerUser(String email) {
        LOGGER.info("Getting user profile for user: {}", email);
        AppUser appUser = userRepository.findByEmail(email).orElseThrow();
        return UserProfileMapper.map(appUser);
    }
}
