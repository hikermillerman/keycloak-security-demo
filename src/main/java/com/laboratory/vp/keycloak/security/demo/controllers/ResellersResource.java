package com.laboratory.vp.keycloak.security.demo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Arrays;

@CrossOrigin(origins = "*", maxAge = 3600)
@Controller
@RequestMapping(path = "api")
public class ResellersResource {
    @GetMapping(path = "resellers")
    public String getProducts(Model model) {
        model.addAttribute("resellers", Arrays.asList("Request Order", "View Orders", "View Codes"));
        return "endpoint/resellers";
    }
}
