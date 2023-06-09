package com.example.base.domain.member.service.user;

import com.example.base.common.exception.BizException;
import com.example.base.domain.member.model.member.Member;

public interface userService {
  /**
   * 회원 정보를 가져온다.
   *
   * @param member
   * @return Member
   * @throws BizException
   */
  Member getUser(Member member) throws BizException;
}
