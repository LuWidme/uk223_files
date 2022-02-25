package ch.noser.uek223ex8.core.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("jwt")
public class JWTProperties {

    private long expirationMillis;
    private String tokenPrefix;
    private String headerName;
    private String issuer;
    private String secret;

    public long getExpirationMillis() {
        return expirationMillis;
    }

    public JWTProperties setExpirationMillis(long expirationMillis) {
        this.expirationMillis = expirationMillis;
        return this;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public JWTProperties setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
        return this;
    }

    public String getHeaderName() {
        return headerName;
    }

    public JWTProperties setHeaderName(String headerName) {
        this.headerName = headerName;
        return this;
    }

    public String getIssuer() {
        return issuer;
    }

    public JWTProperties setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public String getSecret() {
        return secret;
    }

    public JWTProperties setSecret(String secret) {
        this.secret = secret;
        return this;
    }
}
