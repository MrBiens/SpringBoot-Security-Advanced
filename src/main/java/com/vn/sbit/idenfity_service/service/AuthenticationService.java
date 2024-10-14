package com.vn.sbit.idenfity_service.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vn.sbit.idenfity_service.dto.request.AuthenticationRequest;
import com.vn.sbit.idenfity_service.dto.request.IntrospectRequest;
import com.vn.sbit.idenfity_service.dto.response.AuthenticationResponse;
import com.vn.sbit.idenfity_service.dto.response.IntrospectResponse;
import com.vn.sbit.idenfity_service.entity.User;
import com.vn.sbit.idenfity_service.exception.AppException;
import com.vn.sbit.idenfity_service.exception.ErrorCode;
import com.vn.sbit.idenfity_service.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.StringJoiner;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE,makeFinal = true)
public class AuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    UserRepository userRepository;

    //Kiểm tra token có hợp lệ hay không
    public IntrospectResponse introspectResponse(IntrospectRequest request) throws JOSEException, ParseException {
        var token = request.getToken();
        SignedJWT signedJWT = SignedJWT.parse(token);//Phân tích cú pháp chuỗi token thành một đối tượng SignedJWT.

        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());// Private key sử dụng để tái tạo lại signature mới(dùng để so sánh với signature token).

        Date expiryTime=signedJWT.getJWTClaimsSet().getExpirationTime();//Lấy thời gian hết hạn của token từ claims set của JWT.

        var verified=signedJWT.verify(verifier);//trả về true nếu token signature giống với signature được tạo để kiển tra

        return IntrospectResponse.builder()
                .valid(verified && expiryTime.after(new Date()))//Đặt giá trị valid của phản hồi dựa trên việc JWT có được xác minh và thời gian hết hạn còn hiệu lực hay không
                .build();//Xây dựng đối tượng IntrospectResponse và trả về.
    }

    @NonFinal // đánh dấu để lombok không inject dependency vào construct
    @Value("${jwt.signerKey}")//springframework.annotation.Value; // dùng để injection 1 property ở application vào variable
    protected String SIGNER_KEY ;//cipher key-khóa bí mật -generate random

    //Xác thực để trả về token
    public AuthenticationResponse Authenticate(AuthenticationRequest request) {
        var user = userRepository.findByUserName(request.getUserName()).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        //xác thực mật khẩu có khớp với mật khẩu đã lưu
        boolean authenticated= passwordEncoder.matches(request.getPassWord(), user.getPassWord());
        if (!authenticated){
            throw  new AppException(ErrorCode.UNAUTHENTICATED);
        }else{
            var token = generateToken(user);

            return AuthenticationResponse.builder()
                    .token(token)
                    .authenticated(true)
                    .build();
        }

    }

    //Lấy token từ thông tin đã đưa vào
     String generateToken(User user){
        //dependency nimbus Token gồm [header;payload;signature(header,payload)]
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS512); // thuat toan SHA512

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUserName())      //username
                .issuer("com.vn.sbit") //domain
                .issueTime(new Date())  //time create
                .expirationTime(new Date(Instant.now().plus(1, ChronoUnit.HOURS).toEpochMilli()))// expiry time
                .claim("scope",buildScope(user))
                .build();
        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(jwsHeader,payload);//header - payload

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes())); // ký private key signer_key
            return jwsObject.serialize();//trả về objectjwt đc ký thành dạng chuỗi bằng serialize(sẽ được đầy đủ)-gồm header-paypal-signature
        } catch (JOSEException e) {
            log.error("Cannot create token "+e);
            throw new RuntimeException(e);
        }
    }

    //ROLE USER -TOKEN(JWT)
    String buildScope(User user){ //Get user.role and role.permission //Example: "ADMIN  - CREATE UPDATE DELETE"
        StringJoiner stringJoiner = new StringJoiner(" "); // joiner: [""  ,"" ,""]
        if(!CollectionUtils.isEmpty(user.getRoles())) { //IF USER.ROLE NOT NULL
            user.getRoles().forEach(role
                    -> { stringJoiner.add("ROLE_"+role.getName());  // AUTO ADD ROLE_ VÀO TOKEN (TỪ ADMIN -> ROLE_ADMIN)
                if (!CollectionUtils.isEmpty(role.getPermissions())) { //IF ROLE.PERMISSION NOT NULL
                    role.getPermissions().forEach(permission
                            -> { stringJoiner.add("PERMISSION_"+permission.getName());// AUTO ADD PERMISSION VÀO TOKEN (TỪ CREATE -> PERMISSION_CREATE)
                    });
                }
                
            });
        }
        return stringJoiner.toString();
    }

    /*   String buildScope(User user){
                if (!CollectionUtils.isEmpty(user.getRoles())) { //IF USER.ROLE NOT NULL
                for (Role role : user.getRoles()) { // Role of this User
                    stringJoiner.add(role.getName());
                    if (!CollectionUtils.isEmpty(role.getPermissions())) { //IF ROLE.PERMISSION NOT NULL
                        for (Permission permission : role.getPermissions()) { //import class Permission
                            stringJoiner.add(permission.getName());
                            }
                        }
                    }
                }
          }
     */

}
