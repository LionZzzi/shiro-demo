package com.eric.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Eric
 * @date 2019/2/1
 */
@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/view")
    public String view() {
        return "show view";
    }

    @GetMapping("/add")
    public String add() {
        return "show add";
    }
}
