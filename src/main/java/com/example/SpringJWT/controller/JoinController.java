package com.example.SpringJWT.controller;

import com.example.SpringJWT.dto.JoinDto;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {

    @PostMapping("/join")
    public String join(JoinDto joinDto) {

        return "ok";

    }


}
