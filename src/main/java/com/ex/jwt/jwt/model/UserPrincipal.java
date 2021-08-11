package com.ex.jwt.jwt.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

public class UserPrincipal implements UserDetails {
    private User User;

    public UserPrincipal(User User) {
        this.User = User;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//        return stream(User.getAuthorities()).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        String[] arr = new String[] {User.getAuthorities()};
        return stream(arr).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return this.User.getPassword();
    }

    @Override
    public String getUsername() {
        return this.User.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
