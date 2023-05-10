package com.sopt.wokat.domain.member.entity;

import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import com.mongodb.lang.Nullable;
import com.sopt.wokat.global.entity.BaseEntity;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Document(collection = "Member")
@Schema(description = "Member 테이블")
public class Member extends BaseEntity {

 

    @Builder
    public Member(String nickName, String profileImage, String email) {
        this.nickName = nickName;
        this.profileImage = profileImage;
        this.userEmail = email;
    }

    public static Member creatMember(String email, String nickName, String provider, String providerId, String imageUrl) {

    }

}
