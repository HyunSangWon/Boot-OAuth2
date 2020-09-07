package com.sangwon.oauth.conf;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

public enum CustomOAuth2Provider {
	
	KAKAO{
		@Override
		public ClientRegistration.Builder getBuilder(String registrationId) {
			ClientRegistration.Builder builder = getBuilder(registrationId, ClientAuthenticationMethod.POST);
			builder.scope("profile");
			builder.authorizationUri("https://kauth.kakao.com/oauth/authorize");
			builder.tokenUri("https://kauth.kakao.com/oauth/token");
			builder.userInfoUri("https://kapi.kakao.com/v2/user/me");
			builder.userNameAttributeName("id");
			builder.clientName("Kakao");
			return builder;
			}
	};
	
	private static final String DEFAULT_LOGIN_REDIRECT_URL = "http://localhost:8080/login/oauth2/code/kakao";

	protected final ClientRegistration.Builder getBuilder(String registrationId, ClientAuthenticationMethod method) {
		ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
		builder.clientAuthenticationMethod(method);
		builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE); 
		builder.redirectUriTemplate(DEFAULT_LOGIN_REDIRECT_URL);
		return builder; 
	}
	
	public abstract ClientRegistration.Builder getBuilder(String registrationId);

}
