package org.sid.securityservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.securityservice.sec.JWTUtil;
import org.sid.securityservice.sec.entities.AppRole;
import org.sid.securityservice.sec.entities.AppUser;
import org.sid.securityservice.sec.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    @Autowired
    private AccountService accountService;

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")  //L'accès a cet méthode n'accessible que par les users qui ont le role USER
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping("/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping("/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping("/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }

    //Renouveler accès token à partir du refresh token
    @GetMapping("/refreshToken")   //Envoyer à le refreshToken afin de renouvler AccessToken
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //Lire le header authorization
        String authToken = request.getHeader(JWTUtil.AUTH_HEADER);
        if (authToken!=null && authToken.startsWith("Bearer ")){
            try {
                String jwt = authToken.substring(7); //Get Token
                Algorithm algorithm= Algorithm.HMAC256(JWTUtil.SECRET); //Signer le token avec le m clé secrète
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();  //Créer vérifier
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);  //et l'utiliser pour vérifier token
                String username = decodedJWT.getSubject();  //Get username
                AppUser appUser = accountService.loadUserByUsername(username);  //récupérer user
                String jwtAccessToken = JWT.create()      //générer jwt
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken = new HashMap<>();
                //Add ces 2 Token dans idToken
                idToken.put("access-token",jwtAccessToken);
                idToken.put("refresh-token",jwt);
                response.setContentType("application/json"); //indiquer au client que à la corps de la réponse contient des données json
                //envoyer idToken en format json dans la corps de la réponse http
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
            }catch (Exception e) {
                throw e;
            }
        }
        else {
            throw new RuntimeException("Refresh token required!!!");
        }
    }

    //consulter le profil de user authentifié
    @GetMapping("/profile")
    public AppUser profile(Principal principal) {
        return accountService.loadUserByUsername(principal.getName());
    }

}
@Data
class RoleUserForm{
    private String username;
    private String roleName;
}
