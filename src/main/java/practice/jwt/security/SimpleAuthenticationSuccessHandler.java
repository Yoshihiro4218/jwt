package practice.jwt.security;

import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.*;
import lombok.extern.slf4j.*;
import org.springframework.http.*;
import org.springframework.security.core.*;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.*;
import practice.jwt.domain.entity.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;

@Slf4j
public class SimpleAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    final private Algorithm algorithm;

    public SimpleAuthenticationSuccessHandler(String secretKey) {
        Objects.requireNonNull(secretKey, "secret key must be not null");
        try {
            this.algorithm = Algorithm.HMAC256(secretKey);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication auth) throws IOException, ServletException {
        if (response.isCommitted()) {
            log.info("Response has already been committed.");
            return;
        }
        setToken(response, generateToken(auth));
        response.setStatus(HttpStatus.OK.value());
        clearAuthenticationAttributes(request);
    }

    private static final Long EXPIRATION_TIME = 1000L * 60L * 10L;

    private String generateToken(Authentication auth) {
        SimpleLoginUser loginUser = (SimpleLoginUser) auth.getPrincipal();
        Date issuedAt = new Date();
        Date notBefore = new Date(issuedAt.getTime());
        Date expiresAt = new Date(issuedAt.getTime() + EXPIRATION_TIME);
        String token = JWT.create()
                          .withIssuedAt(issuedAt)
                          .withNotBefore(notBefore)
                          .withExpiresAt(expiresAt)
                          .withSubject(loginUser.getUser().getId().toString())
                          .sign(this.algorithm);
        log.debug("generate token : {}", token);
        return token;
    }

    private void setToken(HttpServletResponse response, String token) {
        response.setHeader("Authorization", String.format("Bearer %s", token));
    }

    /**
     * Removes temporary authentication-related data which may have been stored in the
     * session during the authentication process.
     */
    private void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

}
