package com.example.base.common.config.security.model;

import com.example.base.domain.member.model.member.Member;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PrincipalDetail implements UserDetails {
  private Member member;

  public Member getMember() {
    return member;
  }

  public int getIdx() {
    return member.getIdx();
  }

  public String getUserId() {
    return member.getId();
  }

  @Override
  public String getUsername() {
    return member.getName();
  }

  @Override
  public String getPassword() {
    return member.getPw();
  }

  /**
   * 계정 만료 여부
   *
   * @return boolean
   */
  @Override
  public boolean isAccountNonExpired() {
    // true 만료되지 않음
    return true;
  }

  /**
   * 계정 잠금 여부
   *
   * @return boolean
   */
  @Override
  public boolean isAccountNonLocked() {
    // true 잠기지 않음
    return true;
  }

  /**
   * 패스워드 만료 여부
   *
   * @return boolean
   */
  @Override
  public boolean isCredentialsNonExpired() {
    // true 만료되지 않음
    return true;
  }

  /**
   * 계정 활성화 여부
   *
   * @return boolean
   */
  @Override
  public boolean isEnabled() {
    return true;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of();
  }
}
