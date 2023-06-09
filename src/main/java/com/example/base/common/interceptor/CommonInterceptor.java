package com.example.base.common.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@Slf4j
public class CommonInterceptor implements HandlerInterceptor {
  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    long trId = System.currentTimeMillis();
    request.setAttribute("TRID", trId);

    String lang = LocaleContextHolder.getLocale().getLanguage();
    request.setAttribute("LANG", lang);

    log.info("#####REQUEST[{}] : {}, {}, {}, {}]", trId, request.getRequestURI(), request.getMethod(),
            request.getQueryString(), request.getContentType());

    if ("POST,GET,PUT,DELETE".contains(request.getMethod())) {
      log.info("[{}]Host            = {}", trId, request.getRemoteHost());
      log.info("[{}]User-Agent      = {}", trId, request.getHeader("user-agent"));
      log.info("[{}]Accept-Language = {}", trId, request.getHeader("Accept-Language"));
      log.info("[{}]Lang            = {}", trId, lang);
    }

    return HandlerInterceptor.super.preHandle(request, response, handler);
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                              Object handler, Exception ex) {

    long trId = (long) request.getAttribute("TRID");
    log.info("#####REQUEST_END[{}] : {}ms", trId, System.currentTimeMillis() - trId);
  }

}
