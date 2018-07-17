package org.ict.crms.core.crmszuul;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;

/**
 * @author akira.eisen@gmail.com
 *
 */
public class TokenFilter implements Filter {

    public static final String AUTH_HEADER = "Authorization";
    public static final String KEY_PPROVIDER = "KEY_PROVIDER";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;

        // get token from header
        String auth_token = request.getHeader(TokenFilter.AUTH_HEADER);

        if (auth_token == null) {

            // return invalidate token error!
            servletResponse.getWriter().print("invalidate token!");

            servletResponse.getWriter().flush();

            return;
        }

        // construct verifier
        JwkProvider provider = (JwkProvider)request.getServletContext().getAttribute(TokenFilter.KEY_PPROVIDER);

        if (provider == null) {

            // 没有创建过Provider
            URL url = new URL("http://10.1.20.247:8080/auth/realms/CRMS/protocol/openid-connect/certs");

            JwkProvider http = new UrlJwkProvider(url);

            provider = new GuavaCachedJwkProvider(http);

            request.getServletContext().setAttribute(TokenFilter.KEY_PPROVIDER, provider);

        }

        Jwk jwk;
        RSAPublicKey ras;
        try {

            jwk = provider.get("");

            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey)jwk.getPublicKey(), null);

            JWTVerifier verifier = JWT.require(algorithm).build();

            DecodedJWT TOKEN = verifier.verify(auth_token);

        } catch (JwkException e) {

            System.out.println("ERROR: get jwk error!");

            e.printStackTrace();

            return;
        }
    }

    @Override
    public void destroy() {

    }
}
