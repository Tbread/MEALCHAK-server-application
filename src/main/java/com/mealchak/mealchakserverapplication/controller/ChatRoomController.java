package com.mealchak.mealchakserverapplication.controller;

import com.mealchak.mealchakserverapplication.model.*;
import com.mealchak.mealchakserverapplication.oauth2.UserDetailsImpl;
import com.mealchak.mealchakserverapplication.service.ChatMessageService;
import com.mealchak.mealchakserverapplication.service.ChatRoomService;
import com.mealchak.mealchakserverapplication.service.PostService;
import com.mealchak.mealchakserverapplication.service.UserRoomService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
public class ChatRoomController {

    private final ChatRoomService chatRoomService;
    private final ChatMessageService chatMessageService;
    private final UserRoomService userRoomService;


    // 사용자별 채팅방 목록 조회
    @GetMapping("/chat/rooms/mine")
    public List<ChatRoom> getOnesChatRoom(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        return chatRoomService.getOnesChatRoom(userDetails.getUser());
    }

    // 해당 채팅방의 메세지 조회
    @GetMapping("/chat/{roomId}/messages")
    public Page<ChatMessage> getRoomMessage(@PathVariable String roomId, @PageableDefault Pageable pageable) {
        return chatMessageService.getChatMessageByRoomId(roomId, pageable);
    }

    //채팅방에 입장
    @GetMapping("/chat/join/{id}")
    public void joinChatRoom(@PathVariable String stringPostId, @AuthenticationPrincipal UserDetailsImpl userDetails) {
        UserRoom userRoom = new UserRoom();
        userRoom.setUserId(userDetails.getUser().getUserId());
        Long longPostId = Long.parseLong(stringPostId);
        ChatRoom chatRoom = chatRoomService.findByPostId(longPostId);
        userRoom.setRoomId(chatRoom.getRoomId());
        userRoomService.save(userRoom);
    }


//    //필요없을것같지만 테스트를위해
//    @PostMapping("/chat/getall")
//    @ResponseBody
//    public List<ChatRoom> room(){
//        return chatRoomService.getAll();
//    }
}
