package practice.jwt.controller;

import org.springframework.http.*;
import org.springframework.security.core.*;
import org.springframework.security.core.annotation.*;
import org.springframework.web.bind.annotation.*;
import practice.jwt.domain.entity.*;

@RestController
@RequestMapping("/user")
public class TestController {

    @GetMapping("/test1")
    public ResponseEntity getHello(@AuthenticationPrincipal(expression = "user") User user) {
        return ResponseEntity.ok("Hello!! " + user.getName());
    }
}
