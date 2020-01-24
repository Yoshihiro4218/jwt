package practice.jwt.security;

import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.*;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.*;

import java.io.*;
import java.util.*;

public class JwtToken {

    private static final Long EXPIRATION_TIME = 1000L * 60L * 10L;

    public void build() {
        String secretKey = "secret";
        Date issuedAt = new Date();
        Date notBefore = new Date(issuedAt.getTime());
        Date expiresAt = new Date(issuedAt.getTime() + EXPIRATION_TIME);

        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            String token = JWT.create()
                              // registered claims
                              //.withJWTId("jwtId")        //"jti" : JWT ID
                              //.withAudience("audience")  //"aud" : Audience
                              //.withIssuer("issuer")      //"iss" : Issuer
                              .withSubject("test")         //"sub" : Subject
                              .withIssuedAt(issuedAt)      //"iat" : Issued At
                              .withNotBefore(notBefore)    //"nbf" : Not Before
                              .withExpiresAt(expiresAt)    //"exp" : Expiration Time
                              //private claims
                              .withClaim("X-AUTHORITIES", "aaa")
                              .withClaim("X-USERNAME", "bbb")
                              .sign(algorithm);
            System.out.println("generate token : " + token);
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public void verify() {
        String secretKey = "secret";
        String token = "";

        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            JWTVerifier verifier = JWT.require(algorithm).build();

            DecodedJWT jwt = verifier.verify(token);

            // registered claims
            String subject = jwt.getSubject();
            Date issuedAt = jwt.getIssuedAt();
            Date notBefore = jwt.getNotBefore();
            Date expiresAt = jwt.getExpiresAt();
            System.out.println("subject : [" + subject + "] issuedAt : [" + issuedAt.toString() + "] notBefore : [" + notBefore.toString() + "] expiresAt : [" + expiresAt.toString() + "]");
            // subject : [test] issuedAt : [Thu Apr 12 13:19:00 JST 2018] notBefore : [Thu Apr 12 13:19:00 JST 2018] expiresAt : [Thu Apr 12 13:29:00 JST 2018]

            // private claims
            String authorities = jwt.getClaim("X-AUTHORITIES").asString();
            String username = jwt.getClaim("X-USERNAME").asString();
            System.out.println("private claim  X-AUTHORITIES : [" + authorities + "] X-USERNAME : [" + username + "]");
            // private claim  X-AUTHORITIES : [aaa] X-USERNAME : [bbb]

        }
        catch (UnsupportedEncodingException | JWTVerificationException e) {
            e.printStackTrace();
        }
    }
}
