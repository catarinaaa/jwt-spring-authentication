package org.example.authentication.registration;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "api/v1/registration")
public class RegistrationController {

    private final RegistrationService registrationService;

    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping
    public String register(@RequestBody RegistrationRequest request) {
        return registrationService.register(request);
    }

    @GetMapping("/confirm")
    public ResponseEntity<String> confirm(@RequestParam("token") String token) {
        return ResponseEntity.ok(registrationService.confirmToken(token));
    }

    @PostMapping("/reset")
    public String resetPassword(@RequestBody ResetPasswordRequest request) {
        // generate token for resetting password
        return registrationService.resetPassword(request);
    }

    @GetMapping("/reset/{token}")
    public void validatePasswordToken(@PathVariable("token") String token) {
        // validate token
        registrationService.validatePasswordToken(token);
    }

    @PostMapping("/reset/{token}")
    public ResponseEntity<String> setNewPassword(@RequestBody SetPasswordRequest request, @PathVariable("token") String token) {
        // reset password
        return ResponseEntity.ok(registrationService.setNewPassword(request, token));
    }

    @GetMapping("/resend")
    public String resendToken(@RequestParam("email") String email) {
        return registrationService.resendToken(email);
    }
}
