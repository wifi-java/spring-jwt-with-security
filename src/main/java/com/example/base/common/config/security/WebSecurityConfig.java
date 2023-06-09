package com.example.base.common.config.security;

import com.example.base.common.config.security.filter.JwtAuthenticationFilter;
import com.example.base.common.config.security.handler.CustomAccessDeniedEntryPoint;
import com.example.base.common.config.security.service.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@RequiredArgsConstructor
@Configuration
public class WebSecurityConfig {
  @Qualifier("SHA512PasswordEncoder")
  private final PasswordEncoder passwordEncoder;

  @Qualifier("jwtServiceImpl")
  private final JwtService jwtService;
  private final CustomAccessDeniedEntryPoint customAccessDeniedEntryPoint;

  @Bean
  public WebSecurityCustomizer configure() {
    // Spring Security를 적용하지 않을 리소스를 설정
    return (web) -> web.ignoring()
            .requestMatchers("/css/**")
            .requestMatchers("/js/**");

  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
            // cors 설정
            //.cors()
            //.configurationSource(corsConfigurationSource())
            //.and()

            .authorizeHttpRequests()

            // 매치 되는 url public 하게 접근 허용
            .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-resources/**").permitAll()
            .requestMatchers("/api/member/v1/sign-up").permitAll()
            .requestMatchers("/api/member/v1/login").permitAll()
            .requestMatchers("/api/member/v1/issue-access-token").permitAll()
            .requestMatchers("/login").permitAll()
            .requestMatchers("/sign-up").permitAll()
            .requestMatchers("/").permitAll()

            // 인증된 사용자만 접근 허용
            .anyRequest()
            .authenticated()
            .and()

            .formLogin().disable()
            .httpBasic().disable()
            .exceptionHandling().authenticationEntryPoint(customAccessDeniedEntryPoint)
            .and()
            // Cross-Site Request Forgery 비활성화
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            // UsernamePasswordAuthenticationFilter 이전에 JwtAuthenticationFilter가 동작하도록 등록
            .addFilterBefore(new JwtAuthenticationFilter(jwtService), UsernamePasswordAuthenticationFilter.class)
            .build();
  }

  // CORS 설정
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // 쿠키를 받을건지
    configuration.setAllowCredentials(false);

    // 허용할 도메인 url
    configuration.setAllowedOrigins(Arrays.asList("http://localhost:8080"));

    // 허용할 method
    configuration.setAllowedMethods(Arrays.asList("*"));

    // 허용할 header
    configuration.addAllowedHeader("*");

    // 클라이언트로 내려줄때 허용할 header
    configuration.setExposedHeaders(Arrays.asList("*"));

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;

  }
}
