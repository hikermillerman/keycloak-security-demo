package com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@ComponentScan(
        basePackageClasses = KeycloakSecurityComponents.class)
@EnableWebSecurity
class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
    private UnauthorizedHandlerConfig unauthorizedHandlerConfig;

    @Autowired
    public void setUnauthorizedHandlerConfig(UnauthorizedHandlerConfig unauthorizedHandlerConfig) {
        this.unauthorizedHandlerConfig = unauthorizedHandlerConfig;
    }

    /**
     * Registers the KeycloakAuthenticationProvider with the authentication manager.
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    @Bean
    public KeycloakConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    /**
     * Defines the session authentication strategy.
     */
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.csrf().disable();
        http
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/resellers*").hasRole("RESELLER")
                .antMatchers(HttpMethod.GET,"/distributors*").hasRole("DISTRIBUTOR")
                .antMatchers(HttpMethod.GET, "/api/something*").hasRole("RESELLER")
                .antMatchers(HttpMethod.POST, "/api/supply*").hasRole("RESELLER")
                .anyRequest().authenticated();
        http
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandlerConfig).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}
