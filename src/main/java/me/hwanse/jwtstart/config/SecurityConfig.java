package me.hwanse.jwtstart.config;

import me.hwanse.jwtstart.jwt.JwtAccessDeniedHandler;
import me.hwanse.jwtstart.jwt.JwtAuthenticationEntryPoint;
import me.hwanse.jwtstart.jwt.JwtSecurityConfig;
import me.hwanse.jwtstart.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final TokenProvider tokenProvider;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

  public SecurityConfig(TokenProvider tokenProvider, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
    JwtAccessDeniedHandler jwtAccessDeniedHandler) {
    this.tokenProvider = tokenProvider;
    this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .csrf().disable()
      .exceptionHandling()
      .accessDeniedHandler(jwtAccessDeniedHandler)
      .authenticationEntryPoint(jwtAuthenticationEntryPoint)
    .and()
      .headers()
      .frameOptions()
      .sameOrigin()
    .and()
      .sessionManagement()
      .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // JWT ?????? ?????????????????? ????????? ????????? ???????????? ?????????
    .and()
      .authorizeRequests()  // 'HttpServletRequest??? ???????????? ???????????? ?????? ??????????????? ???????????????' ?????? ??????
      .antMatchers("/api/hello").permitAll()
      .antMatchers("/api/authenticate").permitAll()
      .antMatchers("/api/signup").permitAll()
      .anyRequest().authenticated() // '?????? ????????? ???????????? ????????? ???????????????' ?????? ??????
    .and()
      .apply(new JwtSecurityConfig(tokenProvider))  // JwtConfig??? ?????? ??????
//      .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class)
    ;
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web
      .ignoring()
      .antMatchers("/h2-console/**", "/favicon.ico", "/error");
  }
}
