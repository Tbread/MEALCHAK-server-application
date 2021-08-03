package com.mealchak.mealchakserverapplication.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.mealchak.mealchakserverapplication.dto.request.UserInfoUpdateDto;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor
public class User extends Timestamped {
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    @Column(name="user_id")
    private Long id;

    @Column(nullable = false)
    @JsonIgnore
    private Long kakaoId;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    @JsonIgnore
    private String password;

    @Column(nullable = false)
    @JsonIgnore
    private String email;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String profileImg;

    @Column(nullable = true)
    private String comment;

    @Embedded
    @JsonIgnore
    private Location location;

    @Column
    private Long fileId;

    public void updateUserInfo(UserInfoUpdateDto updateDto) {
        this.username = updateDto.getUsername();
        this.comment = updateDto.getComment();

    public void updateUsername(String newUsername) {
        this.username = newUsername;
    }

    public void updateUserDisc(Location location) {
        this.location = location;
    }

    public User(Location location) {
        this.location = location;
    }

    public void updateUserImg(Long fileId, String filePath) {
        this.fileId = fileId;
        this.profileImg = filePath;
    }

    public User(String Username, String password) {
        this.kakaoId = 123L;
        this.username = Username;
        this.password = password;
        this.email = Username;
        this.profileImg = "http://115.85.182.57:8080/image/profileDefaultImg.jpg";
        this.location = new Location("강남구", 37.49791, 127.027678);
    }

    public User(Long kakaoId, String Username, String password, String email,  String profileImg,
                Location location) {
        this.kakaoId = kakaoId;
        this.username = Username;
        this.password = password;
        this.email = email;
        this.profileImg = profileImg;
        this.location = location;
    }
}
