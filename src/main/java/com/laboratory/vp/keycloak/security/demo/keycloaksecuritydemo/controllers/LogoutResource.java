package com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Controller
public class LogoutResource {
    @GetMapping(path = "logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession();
        try {
            session.invalidate();
            request.logout();
        } catch (ServletException e) {
            e.printStackTrace();
        }
        return "/endpoint/main";
    }
}
