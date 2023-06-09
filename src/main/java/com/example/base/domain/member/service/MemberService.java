package com.example.base.domain.member.service;

import com.example.base.common.config.security.model.PrincipalDetail;
import com.example.base.common.config.security.service.jwt.JwtService;
import com.example.base.common.exception.AuthenticationFailException;
import com.example.base.common.exception.UnauthorizedException;
import com.example.base.common.util.AuthUtils;
import com.example.base.common.util.RequestUtils;
import com.example.base.domain.member.dto.AuthDto;
import com.example.base.domain.member.dto.MemberDto;
import com.example.base.domain.member.dto.SignUpDto;
import com.example.base.domain.member.model.member.Member;
import com.example.base.domain.member.service.auth.AuthenticationService;
import com.example.base.domain.member.service.signup.SignUpService;
import com.example.base.domain.member.service.user.userService;
import com.example.base.domain.member.service.valid.IdentityValidateService;
import com.example.base.domain.member.service.valid.PasswordValidateService;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import static com.example.base.domain.member.dto.SignUpDto.SignReq;

@RequiredArgsConstructor
@Service
@Slf4j
public class MemberService {
  @Qualifier("signUpServiceImpl")
  private final SignUpService signUpService;

  @Qualifier("authenticationServiceImpl")
  private final AuthenticationService authenticationService;

  @Qualifier("userServiceImpl")
  private final userService userService;

  @Qualifier("identityValidateServiceImpl")
  private final IdentityValidateService identityValidateService;

  @Qualifier("passwordValidateServiceImpl")
  private final PasswordValidateService passwordValidateService;

  @Qualifier("jwtServiceImpl")
  private final JwtService jwtService;

  /**
   * 회원 가입
   *
   * @param signReq
   */
  public void signUp(SignReq signReq) {
    Member member = SignUpDto.toEntity(signReq);

    if (member.isNormalChannel()) {
      identityValidateService.validate(member.getId());
      passwordValidateService.validate(member.getPw(), member.getPwConfirm());

      signUpService.checkExistIdentity(member);
      signUpService.signUpForNormal(member);

    } else {
      signUpService.checkExistIdentity(member);
      signUpService.signUpForSocial(member);
    }
  }

  /**
   * 로그인 처리 후 액세스토큰을 내려준다.
   *
   * @param req
   * @return AuthRes
   */
  public AuthDto.AuthRes login(AuthDto.AuthReq req) {
    Member member = AuthDto.toEntity(req);
    PrincipalDetail principalDetail = authenticationService.authentication(member);
    String refreshToken = jwtService.getRefreshToken(principalDetail);
    String accessToken = jwtService.getAccessToken(principalDetail);

    jwtService.saveAuthToken(principalDetail, refreshToken);

    // 리프레시 토큰을 쿠키에 http only로 넣어준다.
    Cookie cookie = new Cookie("refreshToken", refreshToken);

    // 쿠키 만료시간은 리프레시 토큰 만료시간과 동일하게 맞춰준다.
    cookie.setMaxAge(60 * 24 * 60 * 60);
    cookie.setSecure(true);
    cookie.setHttpOnly(true);
    cookie.setPath("/");

    RequestUtils.getResponse().addCookie(cookie);

    AuthDto.AuthRes res = new AuthDto.AuthRes();
    res.setAccessToken(accessToken);

    return res;
  }

  /**
   * 사용자 정보 조회
   *
   * @return MemberDto.InfoRes
   */
  public MemberDto.InfoRes info() {
    try {
      PrincipalDetail principalDetail = AuthUtils.getMemberAuth().orElseThrow(UnauthorizedException::new);
      return MemberDto.toDto(userService.getUser(principalDetail.getMember()));
    } catch (Exception e) {
      throw new UnauthorizedException();
    }
  }

  /**
   * 리프레시 토큰이 유효한지 체크하여 액세스 토큰을 재발급해준다.
   *
   * @return AuthRes
   */
  public AuthDto.AuthRes issueAccessToken() {
    try {
      String refreshToken = RequestUtils.getRequestCookie("refreshToken");

      jwtService.validateToken(refreshToken);
      jwtService.validateStoreRefreshToken(refreshToken);

      PrincipalDetail principalDetail = AuthUtils.getMemberAuth().orElseThrow(AuthenticationFailException::new);
      String accessToken = jwtService.getAccessToken(principalDetail);

      AuthDto.AuthRes res = new AuthDto.AuthRes();
      res.setAccessToken(accessToken);

      return res;
    } catch (Exception e) {
      log.error("", e);

      Cookie cookie = new Cookie("refreshToken", null);
      cookie.setHttpOnly(true);
      cookie.setSecure(true);
      cookie.setPath("/");
      cookie.setMaxAge(0);

      RequestUtils.getResponse().addCookie(cookie);

      throw new AuthenticationFailException();
    }
  }
}
