package com.sopt.wokat.global.entity;

import java.time.LocalDateTime;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Data
@Document(collection = "Base_Entity")
@Schema(description = "공통 필드")
public class BaseEntity {
    
    @Id
    @Field("_id")
    @Schema(description = "유저 ID")
    private String id;

    @CreatedDate
    @Field("created_at")
    @Schema(description = "생성 일자")
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Field("updated_at")
    @Schema(description = "업데이트 일자")
    private LocalDateTime updatedAt;

}
