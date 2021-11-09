package com.example.demo.model.requests;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CreateUserRequest {

	@JsonProperty
	private String username;
	@JsonProperty
	private String password;
	@JsonProperty
	private String confirmedPasswd;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getConfirmedPasswd() {
		return confirmedPasswd;
	}

	public void setConfirmedPasswd(String confirmedPasswd) {
		this.confirmedPasswd = confirmedPasswd;
	}

	public boolean verifyPasswd(){
		if(password.length()<5||!password.equals(confirmedPasswd)) return false;
		return true;
	}
}
