package practice.jwt.security;

import org.springframework.http.*;
import org.springframework.security.access.*;
import org.springframework.security.web.access.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;

public class SimpleAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException exception) throws IOException, ServletException {
        response.sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
    }

}
