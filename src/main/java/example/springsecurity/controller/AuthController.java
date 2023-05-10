package example.springsecurity.controller;

import example.springsecurity.dto.LoginDto;
import example.springsecurity.dto.TokenDto;
import example.springsecurity.jwt.JwtFilter;
import example.springsecurity.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        /** UsernamePasswordAuthenticationToken을 생성  */
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        /** Toekn을 이용해서 Authentication 객체를 생성하려고 authenticate 메소드가 실행이 될때 ladUserByUsername 메서드 실행  */
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        /** SecurityContext에 저장  */
        SecurityContextHolder.getContext().setAuthentication(authentication);

        /** Authentication 객체를 createToken 메서드를 통해서 JWT Token을 생성  */
        String jwt = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();
        /** Response Header에 저장*/
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        /** TokenDto를 이용해서 Response Body에도 저장하여 리턴 */
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}