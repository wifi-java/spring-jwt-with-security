package com.example.base.domain.member.service.user;

import com.example.base.common.exception.BizException;
import com.example.base.common.response.Status;
import com.example.base.domain.member.dao.MemberDao;
import com.example.base.domain.member.model.member.Member;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
@Slf4j
public class userServiceImpl implements userService {
  private final MemberDao memberDao;

  @Override
  public Member getUser(Member member) throws BizException {
    try {
      member = memberDao.selectMember(member).orElseThrow();
    } catch (Exception e) {
      log.error("", e);
      throw new BizException(Status.FAIL, "회원 정보를 가져오는데 실패했습니다.");
    }

    return member;
  }

}
