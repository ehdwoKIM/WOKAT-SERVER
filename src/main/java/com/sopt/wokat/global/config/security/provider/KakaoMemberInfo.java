package com.sopt.wokat.global.config.security.provider;

import java.util.Map;

public class KakaoMemberInfo implements Oauth2MemberInfo {
    
    private Map<String, Object> attributes;

    public KakaoMemberInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getEmail() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getEmail'");
    }

    @Override
    public String getNickName() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getNickName'");
    }

    @Override
    public String getImageURL() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getImageURL'");
    }
    
}
