package security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("{noop}123").roles("USER")
            .and()
            .withUser("admin").password("{noop}123456").roles("ADMIN");
    }
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception { //permitAll tat ca deu co quyen truy cap
        httpSecurity.authorizeRequests().antMatchers("/").permitAll()
            .and().authorizeRequests().antMatchers("/user**").hasRole("USER")
            .and().authorizeRequests().antMatchers("/link1").hasRole("USER")
            .and().authorizeRequests().antMatchers("/admin**").hasRole("ADMIN")
            .and().authorizeRequests().antMatchers("/link1","/link2").hasRole("ADMIN")
            .and()
            .formLogin()
            .and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
    }
}
