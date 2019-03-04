package com.laboratory.vp.keycloak.security.demo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@CrossOrigin(origins = "*", maxAge = 3600)
@Controller
@RequestMapping(path = "api")
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
