package com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Arrays;

@Controller
public class DistributorsResource {
    @GetMapping(path = "distributors")
    public String getMyFoodOptions(Model model) {
        model.addAttribute("distributors", Arrays.asList("Create Activation Codes", "Approve Orders", "Terminate Codes"));
        return "endpoint/distributors";
    }
}
