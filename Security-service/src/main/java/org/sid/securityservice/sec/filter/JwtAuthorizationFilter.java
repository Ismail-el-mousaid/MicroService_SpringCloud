package org.sid.securityservice.sec.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.sid.securityservice.sec.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    //Chaque requete arrive, la méthode doFilterInternal doit etre appelé
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/refreshToken")) {
            filterChain.doFilter(request, response);
        } else {
            //Lire le header authorization
            String authorizationToken = request.getHeader(JWTUtil.AUTH_HEADER);
            if (authorizationToken != null && authorizationToken.startsWith("Bearer ")) {
                try {
                    String jwt = authorizationToken.substring(7); //Get Token
                    Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET); //Signer le token avec le m clé secrète
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();  //Créer vérifier
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);  //et l'utiliser pour vérifier token
                    String username = decodedJWT.getSubject();  //Get username
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class); //Get roles
                    //Transfer ces roles en authorities afin de les stocker dans objet UsernamePass...
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for (String r : roles) {
                        authorities.add(new SimpleGrantedAuthority(r));
                    }
                    //Stocker user dans ce objet
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    //Authentifier ce user
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);  //passer au filtre suivant

                } catch (Exception e) {
                    response.setHeader("error-message", e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            } else {
                filterChain.doFilter(request, response);  //passer au filtre suivant
            }
        }
    }

}
