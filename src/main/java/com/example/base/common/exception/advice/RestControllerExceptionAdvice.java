package com.example.base.common.exception.advice;

import com.example.base.common.exception.AccessDeniedException;
import com.example.base.common.exception.BizException;
import com.example.base.common.exception.UnauthorizedException;
import com.example.base.common.response.ResultData;
import com.example.base.common.response.Status;
import com.example.base.common.util.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class RestControllerExceptionAdvice {
  /**
   * 비즈니스 로직 오류 처리.
   */
  @ExceptionHandler(BizException.class)
  public ResponseEntity<ResultData<?>> handleBizException(HttpServletRequest req, BizException e) {
    log.error("BIZ_EXCEPTION : {} | {}", req.getRequestURI(), e.getMessage());
    Status status = e.getStatus();

    if (RequestUtils.isNativeMobileApp()) {
      // 모바일 네이티브 앱일 경우 Http Status Code 값을 200으로 내려 준다.
      return new ResponseEntity<ResultData<?>>(ResultData.of(status, null), HttpStatus.OK);
    } else {
      return new ResponseEntity<ResultData<?>>(ResultData.of(status, null), HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }


  /**
   * 클라이언트가 인증되지 않았거나 유효한 인증 정보가 부족하여 요청이 거부되었을때 오류 처리
   */
  @ExceptionHandler(UnauthorizedException.class)
  public ResponseEntity<ResultData<?>> handleAccessDeniedExceptionException(HttpServletRequest req, UnauthorizedException e) {
    log.error("UnauthorizedException : {} | {}", req.getRequestURI(), e.getMessage());
    Status status = e.getStatus();

    if (RequestUtils.isNativeMobileApp()) {
      // 모바일 네이티브 앱일 경우 Http Status Code 값을 200으로 내려 준다.
      return new ResponseEntity<ResultData<?>>(ResultData.of(status, null), HttpStatus.OK);
    } else {
      return new ResponseEntity<ResultData<?>>(ResultData.of(status, null), HttpStatus.UNAUTHORIZED);
    }
  }

  /**
   * 권한 없을때 오류 처리.
   */
  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ResultData<?>> handleAccessDeniedExceptionException(HttpServletRequest req, AccessDeniedException e) {
    log.error("AccessDeniedException : {} | {}", req.getRequestURI(), e.getMessage());
    Status status = e.getStatus();

    if (RequestUtils.isNativeMobileApp()) {
      // 모바일 네이티브 앱일 경우 Http Status Code 값을 200으로 내려 준다.
      return new ResponseEntity<ResultData<?>>(ResultData.of(status, null), HttpStatus.OK);
    } else {
      return new ResponseEntity<ResultData<?>>(ResultData.of(status, null), HttpStatus.FORBIDDEN);
    }
  }
}
