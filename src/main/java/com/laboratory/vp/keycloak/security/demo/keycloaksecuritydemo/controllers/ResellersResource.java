package com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Arrays;

@Controller
public class ResellersResource {
    @GetMapping(path = "resellers")
    public String getProducts(Model model) {
        model.addAttribute("resellers", Arrays.asList("Request Order", "View Orders", "View Codes"));
        return "endpoint/resellers";
    }
}
