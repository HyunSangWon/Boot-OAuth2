package com.sangwon.oauth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class OAuth2Contoller {
	
	@GetMapping({"", "/"})
	public String loadMainPage(){
		return "main";
	}
	
	@GetMapping("/login")
	public String loadLoginPage() {
		return "login";
	}
	
	@GetMapping("/login-failure")
	public String loadLoginFailurePage()
	{
		return "loginFailure";
	}
	
	@GetMapping({"/login-success","/hello"})
	public String loginSuccessPage()
	{
		return "hello";
	}
}
