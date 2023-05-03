package com.example.securingapp.sec.security.filters;
import com.example.securingapp.sec.security.JWTUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFiler extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals(JWTUtils.REFRESH_TOKEN_ENDPOINT)){
            filterChain.doFilter(request , response);
        }else {
            String authorizationToken = request.getHeader(JWTUtils.AUTH_HEADER);
            if(authorizationToken !=null && authorizationToken.startsWith(JWTUtils.PREFIX)){
                try{
                    UsernamePasswordAuthenticationToken authenticationToken= JWTUtils.verifyJwtAccessToken(authorizationToken);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request , response);
                }catch (Exception e){
                    response.setHeader("error-message" , e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }else{
                filterChain.doFilter(request , response);
            }
        }

    }
}
