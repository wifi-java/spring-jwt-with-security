package com.example.base.common.util;

import com.example.base.common.config.security.model.PrincipalDetail;
import com.example.base.common.config.security.service.jwt.JwtService;
import com.example.base.common.config.security.service.jwt.impl.JwtServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

@Slf4j
public class AuthUtils {
  /**
   * 로그인된 사용자 정보
   *
   * @return Optional<PrincipalDetail>
   */
  public static Optional<PrincipalDetail> getMemberAuth() {
    PrincipalDetail principalDetail = null;
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      if (authentication.getPrincipal() instanceof PrincipalDetail) {
        principalDetail = (PrincipalDetail) authentication.getPrincipal();
      }

      // 화면 이동시에 헤더에 액세스 토큰이 없을 경우 쿠키에 있는 리프레시 토큰으로 로그인 여부 판단
      // 프론트와 백엔드가 분리되어 있다면 프론트에서 토큰 유무로 로그인 여부 판단할 수 있을테지만...
      // 분리가 안된 상태에서는 화면 이동시에 로그인 여부를 판단할 방법이 마땅치 않다.
      if (principalDetail == null) {
        String refreshToken = RequestUtils.getRequestCookie("refreshToken");

        if (StringUtils.isNotEmpty(refreshToken)) {
          JwtService jwtService = ApplicationContextUtils.getBean(JwtServiceImpl.class);
          authentication = jwtService.getAuthentication(refreshToken);
          principalDetail = (PrincipalDetail) authentication.getPrincipal();
        }
      }

    } catch (Exception ex) {
      log.error("", ex);
    }

    return Optional.ofNullable(principalDetail);
  }

}
