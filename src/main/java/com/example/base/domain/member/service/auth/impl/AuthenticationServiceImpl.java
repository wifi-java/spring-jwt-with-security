package com.example.base.domain.member.service.auth.impl;

import com.example.base.common.config.security.dao.AuthDao;
import com.example.base.common.config.security.model.PrincipalDetail;
import com.example.base.common.exception.AccountDormancyException;
import com.example.base.common.exception.AccountLockException;
import com.example.base.common.exception.LoginFailException;
import com.example.base.domain.member.model.member.Member;
import com.example.base.domain.member.service.auth.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor
@Component
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
  private final AuthDao authDao;
  private final AuthenticationManagerBuilder authenticationManagerBuilder;

  @Override
  public PrincipalDetail authentication(Member member) {
    if (StringUtils.isEmpty(member.getId()) || StringUtils.isEmpty(member.getPw())) {
      throw new LoginFailException();
    }

    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(member.getId(), member.getPw(), List.of());
    Authentication authentication = getAuthentication(authenticationToken);

    PrincipalDetail principalDetail = (PrincipalDetail) authentication.getPrincipal();

    checkAccountDormancy(principalDetail);
    checkAccountLock(principalDetail);

    return principalDetail;
  }

  // AuthenticationManager에 의해 SecurityUserService - (UserDetailsService) 실행되어 아이디, 비밀번호 검증
  private Authentication getAuthentication(UsernamePasswordAuthenticationToken authenticationToken) {
    try {
      return authenticationManagerBuilder.getObject().authenticate(authenticationToken);
    } catch (BadCredentialsException e) {
      throw new LoginFailException();
    }
  }

  // 휴면 계정 상태 체크
  private void checkAccountDormancy(PrincipalDetail principalDetail) {
    if (!principalDetail.isEnabled() || !principalDetail.isAccountNonExpired()) {
      throw new AccountDormancyException();
    }
  }

  // 계정 장금 상태
  private void checkAccountLock(PrincipalDetail principalDetail) {
    if (!principalDetail.isAccountNonLocked()) {
      throw new AccountLockException();
    }
  }
}
