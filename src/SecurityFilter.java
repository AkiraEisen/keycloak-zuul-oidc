package org.ict.crms.core.crmszuul;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.netflix.zuul.context.RequestContext;
import feign.Feign;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.form.FormEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

interface OIDCService {
    @RequestLine("POST /")
    @Headers({"Content-Type: application/x-www-form-urlencoded"})
    public String getToken(
            @Param("grant_type") String grantType,
            @Param("client_id") String clientId,
            @Param("redirect_uri") String redirectUri,
            @Param("code") String code,
            @Param("client_secret") String clientSecret
    );
}

/**
 * @author akira.eisen@gmail.com
 *
 */
@Order(1)
@WebFilter(filterName = "SSO Filter", urlPatterns = "/*")
public class SecurityFilter implements Filter{

    @Value("${realm:CRMS}")
    private  String AUTH_SERVER_REALM; // = "CRMS";

    @Value("${client:core-system-server}")
    private  String CRMS_CORE_CLIENT_ID; // = "core-system-akira";

    @Value("${secret:6aaa2f7a-90db-497a-9654-1d46478fe52e}")
    private  String CRMS_CORE_SECRET; // = "049cea04-4729-4f50-a941-e92f5c3bf516";

    @Value("${keycloak.dev:http://cars.crbim.win:8080/auth/realms/}")
    private  String AUTH_SERVER_BASE; // = "http://10.1.20.247:8080/auth/realms/";

    @Value("${keycloak.dev.inner:http://10.60.1.125:8080/auth/realms/}")
    private  String AUTH_SERVER_BASE_INNER;

    private  String AUTH_SERVER_CODE_URL;

    private  String AUTH_SERVER_TOKEN_URL;

    private  String AUTH_SERVER_CERTS_URL;

    private  String AUTH_SERVER_LOGOUT_URL;

    private  String CRMS_CORE_AUTH_LOGIN = "/crms_core_auth_login/";

    private  String CRMS_CORE_AUTH_LOGOUT = "/crms_core_auth_logout/";

    private  String CRMS_CORE_AUTH_CALLBACK = "/crms_core_auth_callback/";

    private  String CROS_HTTP_REQUEST_METHOD_OPTIONS = "OPTIONS";

    private static OIDCService AUTH_SRV;

    @Autowired
    private RedisTemplate redisTemplate;

    /**
     * 获取Token访问HttpClient服务
     * @return
     */
    private OIDCService authSrv() {
        if(SecurityFilter.AUTH_SRV == null) {
            SecurityFilter.AUTH_SRV = Feign.builder()
                    .encoder(new FormEncoder())
                    .target(OIDCService.class, AUTH_SERVER_TOKEN_URL);

        }
        return SecurityFilter.AUTH_SRV;
    }

    /**
     * 用于获取公钥
     * @return
     */
    private JwkProvider keyProvider() {
        URL url = null;
        JwkProvider jwkProvider = null;
        try {
            url = new URL(AUTH_SERVER_CERTS_URL);
            JwkProvider http = new UrlJwkProvider(url);
            jwkProvider = new GuavaCachedJwkProvider(http);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return jwkProvider;
    }

    /**
     * 从auth server获取公钥，构造rsa 256算法。
     *
     * @param tokenResult
     * @return
     */
    private Algorithm algorithm(String tokenResult) {

        Algorithm algorithm = null;

        if (true) {

            com.google.gson.JsonParser parser = new com.google.gson.JsonParser();

            JsonObject jsonResult = (JsonObject) parser.parse(tokenResult);

            String rowToken = jsonResult.get("id_token").getAsString();

            String headerBase64 = StringUtils.split(rowToken, ".")[0].toString();

            String headerString;
            try {
                // parse header BASE64 error when using sun's base64
                // headerString = new String(java.util.Base64.getDecoder().decode(headerBase64), "UTF-8").trim();
                headerString = new String(org.apache.commons.codec.binary.Base64.decodeBase64(headerBase64), "UTF-8").trim();
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }

            // keycloak certs endpoint
            String keyId = ((JsonObject)parser.parse(headerString)).get("kid").getAsString();

            try {
                algorithm = Algorithm.RSA256((RSAPublicKey)this.keyProvider().get(keyId).getPublicKey(), null);
            } catch (JwkException e) {
                e.printStackTrace();
            }
        }

        return algorithm;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        AUTH_SERVER_CODE_URL = AUTH_SERVER_BASE + AUTH_SERVER_REALM + "/protocol/openid-connect/auth";
        AUTH_SERVER_TOKEN_URL = AUTH_SERVER_BASE_INNER + AUTH_SERVER_REALM + "/protocol/openid-connect/token";
        AUTH_SERVER_CERTS_URL = AUTH_SERVER_BASE_INNER + AUTH_SERVER_REALM + "/protocol/openid-connect/certs";
        AUTH_SERVER_LOGOUT_URL = AUTH_SERVER_BASE + AUTH_SERVER_REALM + "/protocol/openid-connect/logout";
    }

    /**
     *
     * 拦截请求，并做验证鉴权处理。
     *
     * @param req
     * @param resp
     * @param filterChain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(
            ServletRequest req,
            ServletResponse resp,
            FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest)req;

        HttpServletResponse response = (HttpServletResponse)resp;

        final String uri = request.getRequestURI();

        final String referer = request.getHeader("referer");
        // TODO for dev, when prod delete this.
        if("/swagger-ui.html".equals(uri)
                || uri.indexOf("/webjars/") >= 0
                || uri.indexOf("/configuration") >= 0
                || uri.indexOf("/swagger-resources") >= 0
                || uri.indexOf("/api-doc") >= 0) {
            filterChain.doFilter(request, response);
        } else if (referer != null && referer.indexOf("/swagger-ui.html") >= 0) {
            // if request form swagger-ui pass
            filterChain.doFilter(request, response);
        } else{
            // check request method
            if (CROS_HTTP_REQUEST_METHOD_OPTIONS.equals(request.getMethod())) {
                // Pre Request when cros request by browser

                // directly set status ok when pre flight
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);

                String cros = response.getHeader("Access-Control-Allow-Origin");
                if(StringUtils.isEmpty(cros)) {
                    this.cros(request, response);
                }

            } else {
                // Normal Request

                // check action (request uri)
                if(CRMS_CORE_AUTH_LOGIN.equals(uri)) {

                    // get code( open id connect [Authorization Code] mode)
                    if(!this.doAuthCode(request, response)) {
                        // redirect failed
                        this.cros(request, response);
                        response.getWriter().println("登录失败，系统异常! Redirect To Auth Server!");
                    };

                } else if (CRMS_CORE_AUTH_LOGOUT.equals(uri)) {
                    String idToken = request.getParameter("id_token");
                    // 删除Token
                    redisTemplate.opsForHash().delete("TOKENS", idToken);

                    response.sendRedirect(
                            AUTH_SERVER_LOGOUT_URL
                                    + "?redirect_uri=" + request.getRequestURL().toString().split(CRMS_CORE_AUTH_LOGOUT)[0] + CRMS_CORE_AUTH_CALLBACK
                    );
                } else if (CRMS_CORE_AUTH_CALLBACK.equals(uri)) {

                    if (StringUtils.isEmpty(request.getParameter("code"))) {
                        response.sendRedirect(request.getHeader("referer"));
                    } else {
                        // get code callback, request auth server with code for token.
                        if (!this.doAuthToken(request, response)){
                            response.getWriter().println("登录失败，系统异常! Redirect To Client!");
                        };
                    }
                } else if ((CRMS_CORE_AUTH_CALLBACK + "_").equals(uri)) {

                } else {
                    // protected services

                    if(this.checkAuthN(request)) {

                        if(this.checkAuthZ(request)) {

                            try {

                                filterChain.doFilter(request, response);
                                String cros = response.getHeader("Access-Control-Allow-Origin");
                                if(StringUtils.isEmpty(cros)) {
                                    this.cros(request, response);
                                }

                            } catch (Exception e) {
                                System.out.println("系统错误！");
                            }
                        } else {
                            this.cros(request, response);
                            response.setCharacterEncoding("UTF-8");
                            response.setContentType("application/json");
                            response.getWriter().println("{\"code\": 9}");
                            response.getWriter().flush();
                        }

                    } else {
                        this.cros(request, response);
                        response.setCharacterEncoding("UTF-8");
                        response.setContentType("application/json");
                        response.getWriter().println("{\"code\": 8}");
                        response.getWriter().flush();
                    }
                }
            }
        }
    }

    @Override
    public void destroy() {

    }

    /**
     * 向Open ID Connect AuthServer 请求授权码，结果通过指定的redirect_uri返回。
     *
     * @param request
     * @param response
     * @throws Exception
     */
    private boolean doAuthCode(HttpServletRequest request, HttpServletResponse response) {
        StringBuilder uri = new StringBuilder();

        // make request uri.
        uri.append(AUTH_SERVER_CODE_URL)
                // auth code flow
                .append("?response_type=code")
                // open id mode
                .append("&scope=openid")
                // client id
                .append("&client_id=").append(CRMS_CORE_CLIENT_ID)
                // the client server callback endpoint
                .append("&redirect_uri=").append(request.getRequestURL().toString().split(CRMS_CORE_AUTH_LOGIN)[0]).append(CRMS_CORE_AUTH_CALLBACK)
                // addition information for state
                // TODO not in use
                .append("&state=").append(request.getHeader("referer"));

        // redirect to auth server , request for auth code.
        try {

            response.sendRedirect(uri.toString());

        } catch (IOException ioExcep) {
            // redirect failed
            ioExcep.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * 根据Auth Server返回的Code获取Token。
     *
     * @param request
     * @param response
     * @return
     */
    private boolean doAuthToken(HttpServletRequest request, HttpServletResponse response) {

        // do token request
        String tokens = this.authSrv().getToken(
                "authorization_code",
                "" + CRMS_CORE_CLIENT_ID,
                request.getRequestURL().toString(),
                "" + request.getParameter("code"), // auth code form auth server by doAuthCode request.
                "" + CRMS_CORE_SECRET
        );

        // the object for checking jwt.
        JWTVerifier verifier = JWT.require(this.algorithm(tokens)).build();

        JsonParser parser = new JsonParser();

        JsonObject jsonResult = (JsonObject) parser.parse(tokens);

        // checking jwt
        DecodedJWT TOKEN = verifier.verify(jsonResult.get("id_token").getAsString());

        try {
            String uuid = UUID.randomUUID().toString();

            redisTemplate.opsForHash().put("TOKENS", uuid, TOKEN.getPayload());

            // redirect to client with id_token.
            response.sendRedirect(request.getParameter("state") + "?id_token=" + uuid);

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * 用户认证。
     *
     * @param request
     * @return
     */
    private boolean checkAuthN(HttpServletRequest request) {
        String authHeader = request.getHeader("authorization");
        RequestContext requestContext = RequestContext.getCurrentContext();
        try {
            String payload = (String)redisTemplate.opsForHash().get("TOKENS", authHeader);
            if(StringUtils.isEmpty(payload)) {
                return false;
            }
            requestContext.addZuulRequestHeader("auth_token", payload);
            requestContext.addZuulRequestHeader("authorization", authHeader);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    /**
     * 用户鉴权。
     * @param request
     * @return
     */
    private boolean checkAuthZ(HttpServletRequest request) {
        // TODO check service
        return true;
    }


    /**
     * 解决跨域
     * @param request
     * @param response
     */
    private void cros(HttpServletRequest request, HttpServletResponse response) {
//
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Authorization, Accept");
    }
}