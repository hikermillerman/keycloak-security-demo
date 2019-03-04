package com.laboratory.vp.keycloak.security.demo.config;

import com.laboratory.vp.keycloak.security.demo.polls.security.CustomUserDetailsService;
import com.laboratory.vp.keycloak.security.demo.polls.security.JwtAuthenticationEntryPoint;
import com.laboratory.vp.keycloak.security.demo.polls.security.JwtAuthenticationFilter;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
/*
* https://stackoverflow.com/questions/40258583/using-multiple-websecurityconfigureradapter-with-different-authenticationprovide
http://blog.florian-hopf.de/2017/08/spring-security.html
*
* */
public class MultipleEntryPointsSecurityConfig {
    @Configuration
    @ComponentScan(
            basePackageClasses = KeycloakSecurityComponents.class)
    @Order(2)
    public static class KeyCloakWebSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

        /**
         * Registers the KeycloakAuthenticationProvider with the authentication manager.
         */
        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
            keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
            auth.authenticationProvider(keycloakAuthenticationProvider);
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
            /* Only filter endpoints that match api */
            http.cors().and().csrf().disable();
            http.antMatcher("/endpoint/api/**");
            http
                    .authorizeRequests()
                    .antMatchers(HttpMethod.GET, "/endpoint/api/something/**").hasRole("RESELLER")
                    .antMatchers(HttpMethod.POST, "/endpoint/api/supply/**").hasRole("RESELLER")
                    .anyRequest().authenticated();
        /*
        // This code prevents keycloak from showing the login screen!!
        http
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandlerConfig).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);*/
        }
    }

    @Configuration
    @Order(1)
    public class PollsSecurityConfig extends WebSecurityConfigurerAdapter {

        private CustomUserDetailsService customUserDetailsService;

        private final JwtAuthenticationEntryPoint unauthorizedHandler;

        @Autowired
        public PollsSecurityConfig(CustomUserDetailsService customUserDetailsService, JwtAuthenticationEntryPoint unauthorizedHandler) {
            this.customUserDetailsService = customUserDetailsService;
            this.unauthorizedHandler = unauthorizedHandler;
        }

        @Bean
        public JwtAuthenticationFilter jwtAuthenticationFilter() {
            return new JwtAuthenticationFilter();
        }

        @Override
        public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
            authenticationManagerBuilder
                    .userDetailsService(customUserDetailsService)
                    .passwordEncoder(passwordEncoder());
        }

        @Bean(BeanIds.AUTHENTICATION_MANAGER)
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            /* Only filter endpoints that match polls */
            http.cors().and().csrf().disable();
            http.antMatcher("/endpoint/polls/**");
            http
                    .authorizeRequests()
                    .antMatchers(HttpMethod.POST, "/endpoint/polls/signin/**").permitAll()
                    .antMatchers(HttpMethod.POST, "/endpoint/polls/signup/**").hasRole("ADMIN")
                    .antMatchers(HttpMethod.POST, "/endpoint/polls/create/**").hasRole("USER")
                    .anyRequest()
                    .authenticated();
            http
                    .exceptionHandling()
                    .authenticationEntryPoint(unauthorizedHandler)
                    .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            // Add our custom JWT security filter
            http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        }
    }
}
