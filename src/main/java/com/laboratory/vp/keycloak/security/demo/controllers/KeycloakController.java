package com.laboratory.vp.keycloak.security.demo.controllers;

import com.laboratory.vp.keycloak.security.demo.models.ApiRequest;
import com.laboratory.vp.keycloak.security.demo.models.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@Slf4j
@RestController
@RequestMapping(path = "api")
public class KeycloakController {
    @PostMapping(path = "supply")
    public ResponseEntity<ApiResponse> process(@RequestBody ApiRequest apiRequest) {
        log.info("Api request {}", apiRequest.toString());
        ApiResponse apiResponse = new ApiResponse();
        apiResponse.setCode("success");
        return ResponseEntity.ok(apiResponse);
    }

    @GetMapping(path = "something")
    public ResponseEntity<String> getSomething() {
        return ResponseEntity.ok("working");
    }
}
