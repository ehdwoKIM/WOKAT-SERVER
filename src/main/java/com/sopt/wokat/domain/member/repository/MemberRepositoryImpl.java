package com.sopt.wokat.domain.member.repository;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Repository;

import com.sopt.wokat.domain.member.dto.OauthResponse;
import com.sopt.wokat.domain.member.dto.ProfileImageUploadDTO;
import com.sopt.wokat.domain.member.entity.Member;
import com.sopt.wokat.infra.aws.DownlaodFileS3Uploader;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class MemberRepositoryImpl implements MemberRepositoryCustom {
    
    private final Logger LOGGER = LogManager.getLogger(this.getClass());
    
    @Autowired
    private MongoTemplate mongoTemplate;

    @Autowired
    private DownlaodFileS3Uploader downlaodFileS3Uploader;

    public MemberRepositoryImpl(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    @Override
    public Member setProfileImage(OauthResponse oauthResponse) throws IOException {
        ProfileImageUploadDTO imageUploadDTO = downlaodFileS3Uploader.uploadS3ProfileImage(
                    oauthResponse.getOauthProfileImageURL());
        
        //! set 프로필이미지
        oauthResponse.getMember().setProfileImage(
            oauthResponse.getOauthProfileImageURL(),
            imageUploadDTO.getS3ImageURL());

        mongoTemplate.save(oauthResponse.getMember());
        return oauthResponse.getMember();
    }

    @Override
    public Member updateProfileImage(Member member, String oauthProfileImageURL) throws IOException {
        //* S3 객체 삭제
        downlaodFileS3Uploader.deleteObject(member.getProfileImage().getS3URL().split("kakao/")[1]);

        //! DB 업데이트
        Member updatedMember = this.setProfileImage(new OauthResponse(member, oauthProfileImageURL));
        mongoTemplate.save(updatedMember);
        return updatedMember;
    }

}

