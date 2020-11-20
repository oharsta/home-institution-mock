package home;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

@org.springframework.context.annotation.Configuration
public class Configuration extends WebSecurityConfigurerAdapter {

    //https://www.baeldung.com/spring-security-oauth-resource-server
    //https://dev.to/toojannarong/spring-security-with-jwt-the-easiest-way-2i43
    /*
    https://dev.to/toojannarong/spring-security-with-jwt-the-easiest-way-2i43
https://github.com/tomakehurst/wiremock/issues/684
https://www.baeldung.com/spring-security-oauth-resource-server
https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig

     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeRequests(authz -> authz
                        .antMatchers(HttpMethod.GET, "/persons/**").hasAuthority("SCOPE_openid")
//                        .antMatchers(HttpMethod.POST, "/foos").hasAuthority("SCOPE_write")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) ;
    }
}
