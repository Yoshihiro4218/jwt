package practice.jwt.config;

import lombok.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.authentication.builders.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.config.http.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.factory.*;
import org.springframework.security.crypto.password.*;
import org.springframework.security.web.*;
import org.springframework.security.web.access.*;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.*;
import org.springframework.web.filter.*;
import practice.jwt.domain.repository.*;
import practice.jwt.domain.service.*;
import practice.jwt.security.*;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserRepository userRepository;

    private static String SECRET_KEY = "mySecret";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            // AUTHORIZE
            .authorizeRequests()
                .mvcMatchers("/hello/**")
                    .permitAll()
                .mvcMatchers("/user/**")
                    .hasRole("USER")
                .mvcMatchers("/admin/**")
                    .hasRole("ADMIN")
                .anyRequest()
                    .authenticated()
            .and()
            // EXCEPTION
            .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler())
            .and()
            // LOGIN
            .formLogin()
                .loginProcessingUrl("/login").permitAll()
                    .usernameParameter("email")
                    .passwordParameter("pass")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
            .and()
            // ★2 LOGOUT
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler())
            .and()
            // ★3 CSRF
            .csrf()
                .disable()
            // ★4 AUTHORIZE
            .addFilterBefore(tokenFilter(), UsernamePasswordAuthenticationFilter.class)
            // ★5 SESSION
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            ;
        // @formatter:on
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.eraseCredentials(true)
            .userDetailsService(simpleUserDetailService())
            .passwordEncoder(passwordEncoder());
    }

    @Bean("simpleUserDetailService")
    UserDetailsService simpleUserDetailService() {
        return new SimpleUserDetailService(userRepository);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    GenericFilterBean tokenFilter() {
        return new SimpleTokenFilter(userRepository, SECRET_KEY);
    }

    AuthenticationEntryPoint authenticationEntryPoint() {
        return new SimpleAuthenticationEntryPoint();
    }

    AccessDeniedHandler accessDeniedHandler() {
        return new SimpleAccessDeniedHandler();
    }

    AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new SimpleAuthenticationSuccessHandler(SECRET_KEY);
    }

    AuthenticationFailureHandler authenticationFailureHandler() {
        return new SimpleAuthenticationFailureHandler();
    }

    LogoutSuccessHandler logoutSuccessHandler() {
        return new HttpStatusReturningLogoutSuccessHandler();
    }

}
