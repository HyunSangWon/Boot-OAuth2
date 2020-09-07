package com.sangwon.oauth.conf;

import static com.sangwon.oauth.conf.SocialType.KAKAO;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
		.antMatchers("/kakao").hasAuthority(KAKAO.getRoleType())
		.anyRequest().authenticated()
			.and()
		.oauth2Login()
		.userInfoEndpoint()
		.userService(new CustomOAuth2UserService())
			.and() 
		.defaultSuccessUrl("/login-success")
		.failureUrl("/login-failure")
			.and() 
		.exceptionHandling()
		.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository
	(@Value("${custom.oauth2.kakao.client-id}") String kakaoClientId,
	@Value("${custom.oauth2.kakao.client-secret}") String kakaoClientSecret){

		List<ClientRegistration> registrations = new ArrayList<>();
		registrations.add(CustomOAuth2Provider.KAKAO.getBuilder("kakao")
				.clientId(kakaoClientId)
				.clientSecret(kakaoClientSecret)
				.jwkSetUri("temp") //JWK(JSON Web Key)는 암호화 키를 표현하기 위한 다양한 정보를 담은 JSON 객체에 관한 표준이다.
				.build());

		return new InMemoryClientRegistrationRepository(registrations);
	}




}
