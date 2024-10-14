package com.vn.sbit.idenfity_service.configuration;

import com.vn.sbit.idenfity_service.EnumRoles.Role;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;

@Configuration //cau hinh su dung bean
@EnableWebSecurity // phan quyen bang request
@EnableMethodSecurity//phan quyen bang method
@FieldDefaults(level = AccessLevel.PRIVATE,makeFinal = true)
public class SecurityConfig {
    String [] PUBLIC_ENDPOINT={"/users",
            "/auth/token",
            "auth/introspect"
    };

    @NonFinal // đánh dấu để lombok không inject dependency vào construct
    @Value("${jwt.signerKey}")//springframework.annotation.Value; // dùng để injection 1 property ở application vào variable
    String signerKey ;//

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(request ->//ủy quyền
                request.requestMatchers(HttpMethod.POST,PUBLIC_ENDPOINT).permitAll() // cho phép tất cả
                        .requestMatchers(HttpMethod.GET,"/users/myInfo").hasAnyRole(Role.ADMIN.name(),Role.USER.name())
                        .requestMatchers(HttpMethod.GET,"/users").hasAnyAuthority("ROLE_"+Role.ADMIN.name(),"ROLE_"+Role.MANAGER.name())
//                        .hasRole(Role.ADMIN.name()) //có thể dùng hasRole or hasAuthority -ADMIN
//                        hasAuthority("ROLE_ADMIN")// dùng Authority nếu muốn có Role thì phải converter sang ROLE(gốc là SCOPE)
                        .anyRequest().authenticated()//tất cả yêu cầu phải xác thực -> login rồi mới request
        );
        //login bằng token
        httpSecurity.oauth2ResourceServer(oath2 ->
                oath2.jwt(jwtConfigurer -> jwtConfigurer
                        .decoder(jwtDecoder())// sẽ lấy header và payload ở request rồi matcher với signature(chữ ký) của token user. nếu = chữ ký ban đầu của request thì sẽ match thành công
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())  // hasAuthority

                )
                        .authenticationEntryPoint(new JwtAuthenticationEntryPoint()) //401 JWTAuthenticationEntryPoint class
                        .accessDeniedHandler(new CustomAccessDeniedHandler()) //403 CustomAccessDenied
        );

        // csrf tự động bảo mật bởi filter 1 - chặn những request không hợp lệ - để co the create new user -> muốn truy cập phải bỏ chặn
        httpSecurity.csrf(AbstractHttpConfigurer::disable);//httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable() -(lambda) - bỏ chặn
        return httpSecurity.build();
    }

    //jwtdecoder dùng để lấy private key và mã hóa nó theo thuật toán hs512 để tạo ra chữ ký token jwt nhằm xác minh token của người dùng nhập vào với token hệ thống
    @Bean
    JwtDecoder jwtDecoder() {
        SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(),"HS512");
            return NimbusJwtDecoder
                    .withSecretKey(secretKeySpec)
                    .macAlgorithm(MacAlgorithm.HS512)
                    .build();//chỉ gán giá trị vào chính nó để sử dụng làm xác minh token ở nơi khác , kèm algorithm HS512
    }

    @Bean // dùng cho hasAuthority - converter tu SCOPE to ROLE
    JwtAuthenticationConverter jwtAuthenticationConverter(){
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter= new JwtGrantedAuthoritiesConverter();//grantedConverter
        grantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter authenticationConverter=new JwtAuthenticationConverter();//authenticationConverter
        authenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        return authenticationConverter;
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(10);
    }

}