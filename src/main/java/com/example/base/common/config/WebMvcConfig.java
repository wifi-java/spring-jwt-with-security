package com.example.base.common.config;

import com.example.base.common.interceptor.CommonInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@RequiredArgsConstructor
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

  private final CommonInterceptor commonInterceptor;

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    WebMvcConfigurer.super.addInterceptors(registry);

    registry.addInterceptor(commonInterceptor)
            .excludePathPatterns("/css/**", "/images/**", "/js/**");
  }
}
