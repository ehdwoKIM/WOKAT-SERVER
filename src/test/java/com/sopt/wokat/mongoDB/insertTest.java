package com.sopt.wokat.mongoDB;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.MongoTemplate;

import com.sopt.wokat.domain.user.entity.User;

@SpringBootTest
public class insertTest {
    
    @Autowired
    MongoTemplate mongoTemplate;

    @BeforeEach
    public void init() { }

    @Test
    public void insertTest() {

        User user = User.builder()
            .userId("testID")
            .userPw("testPW")
            .build();

        mongoTemplate.insert(user);
    }

}
