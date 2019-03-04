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
public class DistributorsResource {
    @GetMapping(path = "distributors")
    public String getMyFoodOptions(Model model) {
        model.addAttribute("distributors", Arrays.asList("Create Activation Codes", "Approve Orders", "Terminate Codes"));
        return "endpoint/distributors";
    }
}
