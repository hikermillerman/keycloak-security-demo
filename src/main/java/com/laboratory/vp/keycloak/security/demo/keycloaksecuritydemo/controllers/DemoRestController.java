package com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.controllers;

import com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.models.ApiRequest;
import com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.models.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class DemoRestController {
    @PostMapping(path = "something")
    public ResponseEntity<ApiResponse> process(@RequestBody ApiRequest apiRequest) {
        log.info("Api request", apiRequest);
        ApiResponse apiResponse = new ApiResponse();
        apiResponse.setCode("success");
        return ResponseEntity.ok(apiResponse);
    }
}
