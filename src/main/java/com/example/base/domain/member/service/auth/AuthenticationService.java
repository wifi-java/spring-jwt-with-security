package com.example.base.domain.member.service.auth;

import com.example.base.common.config.security.model.PrincipalDetail;
import com.example.base.domain.member.model.member.Member;

public interface AuthenticationService {
  /**
   * 로그인 처리를 위한 인증
   *
   * @param member
   * @return PrincipalDetail
   */
  PrincipalDetail authentication(Member member);
}
