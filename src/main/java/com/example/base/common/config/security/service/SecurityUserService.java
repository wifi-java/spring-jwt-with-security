package com.example.base.common.config.security.service;

import com.example.base.common.config.security.dao.AuthDao;
import com.example.base.common.config.security.model.PrincipalDetail;
import com.example.base.common.exception.LoginFailException;
import com.example.base.domain.member.model.member.Member;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
@Slf4j
public class SecurityUserService implements UserDetailsService {
  private final AuthDao authDao;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Member member = new Member();
    member.setId(username);

    try {
      member = authDao.selectAccount(member).orElseThrow();
    } catch (Exception e) {
      log.error("", e);
      throw new LoginFailException();
    }

    return PrincipalDetail.builder().member(member).build();
  }

}
