package com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.config;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Component
public class KeycloakLogoutHandler extends SecurityContextLogoutHandler {

    private AdapterDeploymentContext adapterDeploymentContext;

    public KeycloakLogoutHandler(AdapterDeploymentContext adapterDeploymentContext) {
        Assert.notNull(adapterDeploymentContext);
        this.adapterDeploymentContext = adapterDeploymentContext;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication == null) {
            log.warn("Cannot log out without authentication");
            return;
        }
        else if (!KeycloakAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
            log.warn("Cannot log out a non-Keycloak authentication: {}", authentication);
            return;
        }

        handleSingleSignOut(request, response, (KeycloakAuthenticationToken) authentication);
    }

    private void handleSingleSignOut(HttpServletRequest request, HttpServletResponse response, KeycloakAuthenticationToken authenticationToken) {
        HttpFacade facade = new SimpleHttpFacade(request, response);
        KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(facade);
        RefreshableKeycloakSecurityContext session = (RefreshableKeycloakSecurityContext) authenticationToken.getAccount().getKeycloakSecurityContext();
        session.logout(deployment);
    }
}
