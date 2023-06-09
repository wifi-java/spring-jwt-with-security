package com.example.base.common.config.security.service.jwt.impl;

import com.example.base.common.config.security.dao.AuthDao;
import com.example.base.common.config.security.model.PrincipalDetail;
import com.example.base.common.config.security.service.jwt.JwtService;
import com.example.base.common.exception.AuthenticationFailException;
import com.example.base.common.util.RequestUtils;
import com.example.base.domain.member.model.member.AuthTokenEntity;
import com.example.base.domain.member.model.member.Member;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class JwtServiceImpl implements JwtService {
  private final AuthDao authDao;

  @Value("${jwt.issuer}")
  private String issuer;

  @Value("${jwt.secret-key}")
  private String secretkey;

  @Override
  public Authentication getAuthentication(String token) {
    Claims claims = getClaims(token);
    Map<String, Object> map = (Map<String, Object>) claims.get("memberAuth");
    Member member = new Member();
    member.setIdx((Integer) map.get("idx"));
    member.setName((String) map.get("name"));

    PrincipalDetail principalDetail = PrincipalDetail.builder().member(member).build();
    return new UsernamePasswordAuthenticationToken(principalDetail, token, List.of());
  }

  @Override
  public String getAccessToken(PrincipalDetail principalDetail) {
    Date now = new Date();
    Date expiration = Date.from(ZonedDateTime.now().plusHours(1).toInstant());

    return Jwts.builder()
            .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
            .setIssuer(issuer)
            .setIssuedAt(now)
            .setExpiration(expiration)
            .claim("memberAuth", getMemberAuthForAccessToken(principalDetail))
            .signWith(SignatureAlgorithm.HS256, secretkey)
            .compact();
  }

  @Override
  public String getRefreshToken(PrincipalDetail principalDetail) {
    Date now = new Date();
    Date expiration = Date.from(ZonedDateTime.now().plusHours(60 * 24).toInstant());

    return Jwts.builder()
            .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
            .setIssuer(issuer)
            .setIssuedAt(now)
            .setExpiration(expiration)
            .claim("memberAuth", getMemberAuthForRefreshToken(principalDetail))
            .signWith(SignatureAlgorithm.HS256, secretkey)
            .compact();
  }

  @Override
  public boolean validateToken(String token) {
    try {
      Jwts.parser().setSigningKey(secretkey).parseClaimsJws(token);
      return true;
    } catch (Exception e) {
      log.error("", e);
      return false;
    }
  }

  @Override
  public Date getExpiration(String token) {
    Claims claims = null;
    try {
      Jws<Claims> jwt = Jwts.parser().setSigningKey(secretkey).parseClaimsJws(token);
      claims = jwt.getBody();
    } catch (Exception e) {
      if (e instanceof ExpiredJwtException) {
        claims = ((ExpiredJwtException) e).getClaims();
      }
    }

    if (claims != null) {
      return claims.getExpiration();
    }

    return new Date();
  }

  @Override
  public Date getIssueDt(String token) {
    Claims claims = null;
    try {
      Jws<Claims> jwt = Jwts.parser().setSigningKey(secretkey).parseClaimsJws(token);
      claims = jwt.getBody();
    } catch (Exception e) {
      if (e instanceof ExpiredJwtException) {
        claims = ((ExpiredJwtException) e).getClaims();
      }
    }

    if (claims != null) {
      return claims.getIssuedAt();
    }

    return new Date();
  }

  @Override
  @Transactional
  public void saveAuthToken(PrincipalDetail principalDetail, String token) {
    AuthTokenEntity authTokenEntity = getAuthTokenEntity(principalDetail, token);
    try {
      authDao.insertAuthToken(authTokenEntity);
    } catch (Exception e) {
      log.error("", e);
      throw new AuthenticationFailException();
    }
  }

  @Override
  public void validateStoreRefreshToken(String refreshToken) {
    try {
      AuthTokenEntity authTokenEntity = new AuthTokenEntity();
      authTokenEntity.setRefreshToken(refreshToken);

      authDao.selectAuthToken(authTokenEntity).orElseThrow();

    } catch (Exception e) {
      throw new AuthenticationFailException();
    }
  }

  private Claims getClaims(String token) {
    return Jwts.parser()
            .setSigningKey(secretkey)
            .parseClaimsJws(token)
            .getBody();
  }

  /**
   * 액세스토큰에 페이로드로 들어갈 데이터
   *
   * @param principalDetail
   * @return map
   */
  private Map<String, Object> getMemberAuthForAccessToken(PrincipalDetail principalDetail) {
    Map<String, Object> map = new HashMap<>();
    map.put("idx", principalDetail.getIdx());
    map.put("name", principalDetail.getUsername());

    return map;
  }

  /**
   * 리프레시 토큰에 페이로드로 들어갈 데이터
   *
   * @param principalDetail
   * @return map
   */
  private Map<String, Object> getMemberAuthForRefreshToken(PrincipalDetail principalDetail) {
    Map<String, Object> map = new HashMap<>();
    map.put("idx", principalDetail.getIdx());

    return map;
  }

  private AuthTokenEntity getAuthTokenEntity(PrincipalDetail principalDetail, String token) {
    AuthTokenEntity authTokenEntity = new AuthTokenEntity();
    authTokenEntity.setRefreshToken(token);
    authTokenEntity.setMbrIdx(principalDetail.getIdx());
    authTokenEntity.setIp(RequestUtils.getIp());
    authTokenEntity.setAgent(RequestUtils.getUserAgent());
    authTokenEntity.setExpirationDt(getExpiration(token));
    authTokenEntity.setLoginDt(getIssueDt(token));

    return authTokenEntity;
  }

}
