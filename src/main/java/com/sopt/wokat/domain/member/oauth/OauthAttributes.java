package com.sopt.wokat.domain.member.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;

import com.sopt.wokat.domain.member.entity.Member;
import com.sopt.wokat.global.config.security.provider.KakaoMemberInfo;

public enum OauthAttributes {

    @Autowired
    private MongoTemplate mongoTemplate;
    
    KAKAO("kakao") {
        @Override
        public Member of(Map<String, Object> attributes) {
            KakaoMemberInfo kakaoMemberInfo = new KakaoMemberInfo(attributes);
            
            
        }
    }
}
