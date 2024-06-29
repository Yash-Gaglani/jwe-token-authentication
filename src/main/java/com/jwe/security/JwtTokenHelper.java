package com.jwe.security;

import com.jwe.exception.ApplicationException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.validation.constraints.NotEmpty;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtTokenHelper {


    public static final long JWT_TOKEN_VALIDITY = 24 * 60 * 60;

    public static final String USER = "USER";

    private final String SECRET = "3E08B8B49CDDADDE29484E4D9B2ED339";

    public String getSubjectFromToken(String token) {
        return getClaimFromToken(token, JWTClaimsSet::getSubject);
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, JWTClaimsSet::getIssueTime);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, JWTClaimsSet::getExpirationTime);
    }

    private Boolean isTokenExpired(String token)
        throws ApplicationException {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Boolean ignoreTokenExpiration(String token) {
        // here you specify tokens, for that the expiration is ignored
        return false;
    }

    public <T> T getClaimFromToken(String token, Function<JWTClaimsSet, T> claimsResolver) {
        JWTClaimsSet claims;
        try {
            claims = getAllClaimsFromToken(token);
            return claimsResolver.apply(claims);
        } catch (BadJOSEException | ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private JWTClaimsSet getAllClaimsFromToken(String token)
        throws BadJOSEException, ParseException, JOSEException {
        ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<>(SECRET.getBytes());
        JWEKeySelector<SimpleSecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
            JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, jweKeySource);
        jwtProcessor.setJWEKeySelector(jweKeySelector);
        return jwtProcessor.process(token, null);
    }


    @NotEmpty
    private static Map<String, Object> prepareRequiredClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put(USER, "yash");
        //Additional Claims here
        return claims;

    }


    public String generateToken(String subject)
        throws ApplicationException {
        try {
            Map<String, Object> claims = prepareRequiredClaims();
            return doGenerateToken(claims, subject);
        } catch (JOSEException e) {
            throw new ApplicationException("Something went wrong");
        }
    }

    private String doGenerateToken(Map<String, Object> claims, String subject)
        throws JOSEException {
        // claims
        Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject(StringUtils.lowerCase(subject));
        claimsSetBuilder.issueTime(new Date(System.currentTimeMillis()));
        claimsSetBuilder.expirationTime(
            new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000));
        if(claims!=null){
        claims.forEach(claimsSetBuilder::claim);
        }
        JWTClaimsSet claimsSet = claimsSetBuilder.build();

        // payload
        Payload payload = new Payload(claimsSet.toJSONObject());

        // header
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);

        JWEEncrypter encrypter = new DirectEncrypter(SECRET.getBytes());

        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(encrypter);
        return jweObject.serialize();
    }


    public boolean validateToken(String token) throws ApplicationException {
        return !isTokenExpired(token);
    }

}
