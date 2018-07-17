package org.ict.crms.core.crmszuul;

import org.springframework.cloud.netflix.zuul.filters.route.FallbackProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * @author akira.eisen@gmail.com
 *
 */
@Component
public class UserServiceFallbackProvider implements FallbackProvider {

    @Override
    public String getRoute() {
        return "*";
    }

    @Override
    public ClientHttpResponse fallbackResponse(String route, Throwable throwable) {
        return new ClientHttpResponse() {
            @Override
            public HttpStatus getStatusCode() throws IOException {
                return HttpStatus.OK;
            }

            @Override
            public int getRawStatusCode() throws IOException {
                return 200;
            }

            @Override
            public String getStatusText() throws IOException {
                return "OK";
            }

            @Override
            public void close() {

            }

            @Override
            public InputStream getBody() throws IOException {
                // 服务不可访问
                return new ByteArrayInputStream("{\"code\": 7}".getBytes());
            }

            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                headers.setAccessControlAllowCredentials(true);
                // 设置允许访问的头
                List<String> allowHeaders = new ArrayList<String>();
                // Origin, X-Requested-With, Content-Type, Authorization, Accept
                allowHeaders.add("Origin");
                allowHeaders.add("X-Requested-With");
                allowHeaders.add("Content-Type");
                allowHeaders.add("Authorization");
                allowHeaders.add("Accept");
                headers.setAccessControlAllowHeaders(allowHeaders);

                // 设置允许访问的方法
                // "POST, GET, OPTIONS, DELETE, PUT"
                List<HttpMethod> allowMethods = new ArrayList<HttpMethod>();
                allowMethods.add(HttpMethod.GET);
                allowMethods.add(HttpMethod.POST);
                allowMethods.add(HttpMethod.PUT);
                allowMethods.add(HttpMethod.DELETE);
                allowMethods.add(HttpMethod.OPTIONS);
                allowMethods.add(HttpMethod.PATCH);
                headers.setAccessControlAllowMethods(allowMethods);

                // 设置允许访问域
                headers.setAccessControlAllowOrigin("*");
                // 设置最大时间
                headers.setAccessControlMaxAge(3600);
                return headers;
            }
        };
    }
}
