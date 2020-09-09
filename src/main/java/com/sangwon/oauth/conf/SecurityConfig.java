package com.sangwon.oauth.conf;


import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.sangwon.oauth.service.CustomOAuth2UserService;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/css/**", "/script/**", "/image/**");
	}
	
	@Override 
	public void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeRequests()
		.antMatchers("/","/login/**","/auth/**").permitAll()
		.antMatchers("/kakao").hasAuthority("ROLE_KAKAO")
		.antMatchers("/naver").hasAuthority("ROLE_NAVER")
		.antMatchers("/google").hasAuthority("ROLE_GOOGLE")
		.anyRequest().authenticated()
			.and()
		.oauth2Login()
		.userInfoEndpoint()
		.userService(new CustomOAuth2UserService()) //네이버 USER INFO의 응답을 처리하기 위한 설정
			.and() 
		.defaultSuccessUrl("/login-success")
		.failureUrl("/login-failure")
			.and() 
		.exceptionHandling()
		.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository
	(OAuth2ClientProperties oAuth2ClientProperties,
	 @Value("${custom.oauth2.kakao.client-id}") String kakaoClientId,
	 @Value("${custom.oauth2.kakao.client-secret}") String kakaoClientSecret,
	 @Value("${custom.oauth2.naver.client-id}") String naverClientId,
	 @Value("${custom.oauth2.naver.client-id}") String naverClientSecret){

		List<ClientRegistration> registrations = oAuth2ClientProperties
				.getRegistration().keySet().stream()
				.map(client -> getRegistration(oAuth2ClientProperties, client))
				.filter(Objects::nonNull)
				.collect(Collectors.toList());

		registrations.add(CustomOAuth2Provider.KAKAO.getBuilder("kakao")
				.clientId(kakaoClientId)
				.clientSecret(kakaoClientSecret)
				.jwkSetUri("temp") //JWK(JSON Web Key)는 암호화 키를 표현하기 위한 다양한 정보를 담은 JSON 객체에 관한 표준이다.
				.build());

		registrations.add(CustomOAuth2Provider.NAVER.getBuilder("naver")
				.clientId(naverClientId)
				.clientSecret(naverClientSecret)
				.jwkSetUri("temp") //JWK(JSON Web Key)는 암호화 키를 표현하기 위한 다양한 정보를 담은 JSON 객체에 관한 표준이다.
				.build());

		return new InMemoryClientRegistrationRepository(registrations);
	}

	private ClientRegistration getRegistration(OAuth2ClientProperties clientProperties, String client) {

		if("google".equals(client)) {
			OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("google");
			return CommonOAuth2Provider.GOOGLE.getBuilder(client)
					.clientId(registration.getClientId())
					.clientSecret(registration.getClientSecret())
					.scope("email", "profile") .build();
		}
		return null;
	}

}