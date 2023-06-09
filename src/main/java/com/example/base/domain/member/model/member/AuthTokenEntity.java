package com.example.base.domain.member.model.member;

import lombok.Data;

import java.util.Date;


/**
 * @TABLE: TB_AUTH_TOKEN
 */
@Data
public class AuthTokenEntity {
  /**
   * 사용자 넘버
   */
  protected int mbrIdx;

  /**
   * 리프레시 토큰
   */
  protected String refreshToken;

  /**
   * 아이피
   */
  protected String ip;

  /**
   * 에이전트
   */
  protected String agent;

  /**
   * 로그인 시간
   */
  protected Date loginDt;

  /**
   * 만료 시간
   */
  protected Date expirationDt;
}
