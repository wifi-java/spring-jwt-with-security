package com.example.base.common.config.security.handler;

import com.example.base.common.response.ResultData;
import com.example.base.common.response.Status;
import com.example.base.common.util.RequestUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;

@RequiredArgsConstructor
@Component
public class CustomAccessDeniedEntryPoint implements AuthenticationEntryPoint {

  private final ObjectMapper objectMapper;

  @Override
  public void commence(HttpServletRequest request
          , HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

    ResultData<?> resultData = ResultData.of(Status.UNAUTHORIZED);
    String jsonString = objectMapper.writeValueAsString(resultData);

    response.setContentType("text/html; charset=utf-8");
    response.setCharacterEncoding("utf-8");

    if (RequestUtils.isNativeMobileApp()) {
      response.setStatus(HttpStatus.OK.value());
    } else {
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }

    OutputStream out = response.getOutputStream();
    out.write(jsonString.getBytes());

  }
}
