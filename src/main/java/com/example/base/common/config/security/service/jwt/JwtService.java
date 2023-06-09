package com.example.base.common.config.security.service.jwt;

import com.example.base.common.config.security.model.PrincipalDetail;
import org.springframework.security.core.Authentication;

import java.util.Date;

public interface JwtService {

  /**
   * 액세스토큰으로 인증 토큰 생성
   *
   * @param token
   * @return Authentication
   */
  Authentication getAuthentication(String token);

  /**
   * 액세스 토큰 생성 - 만료시간 1시간
   *
   * @param principalDetail
   * @return accessToken
   */
  String getAccessToken(PrincipalDetail principalDetail);

  /**
   * 리프레시 토큰 생성 - 만료시간 2달
   *
   * @param principalDetail
   * @return refreshToken
   */
  String getRefreshToken(PrincipalDetail principalDetail);

  /**
   * 토큰 검증
   *
   * @param token
   * @return boolean
   */
  boolean validateToken(String token);

  /**
   * 토큰에 만료 시간을 가져온다.
   *
   * @param token
   * @return Date
   */
  Date getExpiration(String token);

  /**
   * 토큰에 발급 시간을 가져온다.
   *
   * @param token
   * @return Date
   */
  Date getIssueDt(String token);

  /**
   * 저장소에 리프래시 토큰 정보와 사용자 접속 정보를 저장한다.
   *
   * @param principalDetail
   * @param token
   */
  void saveAuthToken(PrincipalDetail principalDetail, String token);

  /**
   * 리프레시 토큰이 저장소에 있는지 조회한다.
   *
   * @param refreshToken
   */
  void validateStoreRefreshToken(String refreshToken);
}
