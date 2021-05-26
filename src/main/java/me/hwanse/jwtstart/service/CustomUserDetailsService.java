package me.hwanse.jwtstart.service;

import java.util.List;
import java.util.stream.Collectors;
import me.hwanse.jwtstart.domain.User;
import me.hwanse.jwtstart.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  public CustomUserDetailsService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
    return userRepository.findOneWithAuthoritiesByUsername(username)
                          .map(user -> createUser(username, user))
                          .orElseThrow(() -> new UsernameNotFoundException(username + " -> 유저정보를 찾을 수 없습니다."));
  }

  private org.springframework.security.core.userdetails.User createUser(String username, User user) {
    if (!user.isActivated()) {
      throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
    }

    List<SimpleGrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
          .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
          .collect(Collectors.toList());

    return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
      grantedAuthorities);
  }
}
