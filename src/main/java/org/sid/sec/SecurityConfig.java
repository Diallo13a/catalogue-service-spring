package org.sid.sec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

   /* @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        BCryptPasswordEncoder bcpe = getBCPE();
        auth.inMemoryAuthentication().withUser("admin").password(bcpe.encode("1234")).roles("ADMIN","USER");
        auth.inMemoryAuthentication().withUser("user1").password(bcpe.encode("1234")).roles("USER");
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http); // On desactive spring security
        http.csrf().disable(); // desactiver le csrf
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);// on utilise plus les sessions
        http.authorizeRequests().antMatchers("/categories/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/products/**").hasAuthority("USER");
        http.authorizeRequests().anyRequest().authenticated();//Toutes les autres requetes necessitent une authentification
        //http.authorizeRequests().anyRequest().permitAll(); // authorizer toutes les requetes
    }

   /* @Bean
    public BCryptPasswordEncoder getBCPE(){
        return new BCryptPasswordEncoder();
    }*/
}
