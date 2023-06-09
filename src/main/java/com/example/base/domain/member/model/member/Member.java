package com.example.base.domain.member.model.member;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.apache.commons.lang3.StringUtils;

/**
 * 테이블과 별개로 필요한 변수 및 기능을 정의한다.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class Member extends MemberEntity {

  private String pwConfirm;

  /**
   * 일반 회원 가입자인지 SNS 가입지인지 여부
   *
   * @return true: 일반 회원가입자, false: SNS 회원가입자
   */
  public boolean isNormalChannel() {
    return StringUtils.isEmpty(this.channel);
  }


}
