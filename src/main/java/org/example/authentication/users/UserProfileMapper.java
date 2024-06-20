package org.example.authentication.users;

import org.example.authentication.appuser.AppUser;

public class UserProfileMapper {

    public static UserProfile map(AppUser appUser) {
        return new UserProfile(appUser.getEmail(),
                appUser.getFirstName(),
                appUser.getLastName());
    }
}
