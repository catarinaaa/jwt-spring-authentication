package org.example.authentication.registration;

import jakarta.transaction.Transactional;
import org.example.authentication.appuser.AppUser;
import org.example.authentication.appuser.AppUserRole;
import org.example.authentication.appuser.AppUserService;
import org.example.authentication.email.EmailSender;
import org.example.authentication.registration.confirmation_token.ConfirmationToken;
import org.example.authentication.registration.confirmation_token.ConfirmationTokenRepository;
import org.example.authentication.registration.confirmation_token.ConfirmationTokenService;
import org.example.authentication.registration.reset_token.ResetToken;
import org.example.authentication.registration.reset_token.ResetTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class RegistrationService {

    private final EmailValidator emailValidator;
    private final AppUserService appUserService;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailSender emailSender;
    private final ResetTokenRepository resetTokenRepository;
    private final ConfirmationTokenRepository confirmationTokenRepository;

    @Value("${config.resetTokenExpirationTime}")
    private Long resetTokenExpirationTime;

    @Value("${config.origin}")
    private String origin;

    public RegistrationService(EmailValidator emailValidator, AppUserService appUserService, ConfirmationTokenService confirmationTokenService, EmailSender emailSender, ResetTokenRepository resetTokenRepository, ConfirmationTokenRepository confirmationTokenRepository) {
        this.emailValidator = emailValidator;
        this.appUserService = appUserService;
        this.confirmationTokenService = confirmationTokenService;
        this.emailSender = emailSender;
        this.resetTokenRepository = resetTokenRepository;
        this.confirmationTokenRepository = confirmationTokenRepository;
    }

    public String register(RegistrationRequest request) {
        boolean isEmailValid = emailValidator.test(request.email());
        if(!isEmailValid) {
            throw new IllegalStateException("Email not valid");
        }
        String token = appUserService.signUpUser(
                new AppUser(
                        request.firstName(),
                        request.lastName(),
                        request.password(),
                        request.email(),
                        AppUserRole.USER
                ));

        emailSender.send(request.email(), buildEmail(request.firstName(), origin + "/register/confirm?token=" + token), "Confirm your email");
        return token;
    }

    @Transactional
    public String confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationTokenService.findConfirmationToken(token)
                .orElseThrow(() -> new IllegalStateException("Token not found"));

        if(confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("Email already confirmed");
        }

        confirmationToken.setConfirmedAt(LocalDateTime.now());
        confirmationTokenService.saveConfirmationToken(confirmationToken);
        appUserService.enableAppUser(confirmationToken.getAppUser().getEmail());

        return "Email confirmed";
    }

    private String buildEmail(String name, String link) {
        // TODO: build email dynamically
        return "Hello " + name + ","
                + "\n\nPlease confirm your email by clicking on the link below:"
                + "\n" + link;
    }

    public String resetPassword(ResetPasswordRequest request) {
        boolean isEmailValid = emailValidator.test(request.email());

        // we could validate if the email is registered, but it could raise security concerns
        boolean isEmailRegistered = appUserService.isEmailRegistered(request.email());

        // if(!isEmailValid || !isEmailRegistered) {
        if(!isEmailValid || !isEmailRegistered) {
            throw new IllegalStateException("Email not valid");
        }

        // generate token for resetting password
        String token = UUID.randomUUID().toString();

        // create token and save in database
        ResetToken resetToken = new ResetToken(
                token,
                request.email(),
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(resetTokenExpirationTime),
                null
        );
        resetTokenRepository.save(resetToken);

        // send email with token
        emailSender.send(request.email(), buildResetEmail(origin + "/reset/" + resetToken.getToken()), "Reset your password");

        return resetToken.getToken();
    }

    private String buildResetEmail(String link) {
        // TODO: build email dynamically
        return "Hello,"
                + "\n\nYou have requested to reset your password. Click on the link below to reset your password:"
                + "\n" + link;
    }

    public ResetToken validatePasswordToken(String token) {
        ResetToken resetToken = resetTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalStateException("Token not found"));

        if(resetToken.getUsedAt() != null) {
            throw new IllegalStateException("Token already used");
        }

        if(resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("Token expired");
        }

        return resetToken;
    }

    public String setNewPassword(SetPasswordRequest request, String token) {
        // validate token
        ResetToken resetToken = validatePasswordToken(token);

        // validates password
        if(request.password() == null || request.password().isEmpty()) {
            throw new IllegalStateException("Password not valid");
        }

        // reset password
        appUserService.resetPassword(resetToken.getEmail(), request.password());

        // mark token as used
        resetToken.setUsedAt(LocalDateTime.now());
        resetTokenRepository.save(resetToken);

        return "Success";
    }

    public String resendToken(String email) {
        //Needed to throw correct exception
        AppUser user;
        try {
            user = appUserService.loadUserByUsername(email);
        } catch (Exception e) {
            throw new IllegalStateException("User not found");
        }
        ConfirmationToken confirmationToken = confirmationTokenService.findConfirmationTokenByAppUser(user)
                .orElseThrow(() -> new IllegalStateException("Token not found"));

        if(confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("Email already confirmed");
        }

        emailSender.send(email, buildEmail(user.getFirstName(), origin + "/register/confirm?token=" + confirmationToken.getToken()), "Confirm your email");

        return confirmationToken.getToken();
    }
}
