package com.mealchak.mealchakserverapplication.config;

import com.mealchak.mealchakserverapplication.jwt.JwtAuthenticationFilter;
import com.mealchak.mealchakserverapplication.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final JwtTokenProvider jwtTokenProvider;

    //패스워드암호화
    @Bean
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    //로그인 로그아웃 세션관리를 위한 bean
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors();
        http
                .csrf().disable()
                .sessionManagement()
                //계정당 최대 접속가능 세션개수
                .maximumSessions(1)
                //true 시 이전로그인세션종료까지 접속불가, false 시 이전로그인세션삭제후 로그인
                .maxSessionsPreventsLogin(false)
                //중복로그인 이동페이지 경로
                .expiredUrl("/")
                //세션등록
                .sessionRegistry(sessionRegistry());
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();
        http.authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                //컨트롤러 접근
                .antMatchers("/user/**").permitAll()
                .antMatchers("/userInfo/{userId}").permitAll()
                .antMatchers("/search").permitAll()
                .antMatchers(HttpMethod.GET, "/posts").permitAll()
                .antMatchers(HttpMethod.GET, "/posts/{postId}").permitAll()
                .antMatchers("/menu").permitAll()
                .antMatchers("/").permitAll()
                .antMatchers("/favicon.ico").permitAll()
                //이미지파일 접근
                .antMatchers("/image/**").permitAll()
                //웹소켓 접근
                .antMatchers("/chatting/**").permitAll()
                .antMatchers("/sub/**").permitAll()
                .antMatchers("/pub/**").permitAll()
                .antMatchers("/swagger-ui/**").permitAll()
                .antMatchers("/swagger-resources/**").permitAll()
                .antMatchers("/v2/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
    }
}
