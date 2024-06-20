package org.example.authentication.registration.confirmation_token;

import org.example.authentication.appuser.AppUser;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;

    public ConfirmationTokenService(ConfirmationTokenRepository confirmationTokenRepository) {
        this.confirmationTokenRepository = confirmationTokenRepository;
    }

    public Optional<ConfirmationToken> findConfirmationToken(String token) {
        return confirmationTokenRepository.findByToken(token);
    }

    public void saveConfirmationToken(ConfirmationToken token) {
        confirmationTokenRepository.save(token);
    }


    public Optional<ConfirmationToken> findConfirmationTokenByAppUser(AppUser user) {
        return confirmationTokenRepository.findByAppUser(user);
    }
}
