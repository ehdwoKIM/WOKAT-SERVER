package com.sopt.wokat.global.config.security.provider;

public interface Oauth2MemberInfo {

    String getProviderId();
    String getProvider();
    String getEmail();
    String getNickName();
    String getImageURL();
    
}
