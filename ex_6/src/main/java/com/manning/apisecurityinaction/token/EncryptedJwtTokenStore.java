package com.manning.apisecurityinaction.token;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import spark.Request;

import javax.crypto.SecretKey;
import java.sql.Date;
import java.text.ParseException;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

public class EncryptedJwtTokenStore implements TokenStore {
    public static final String AUDIENCE = "https://localhost:4567";
    private final SecretKey encKey;

    public EncryptedJwtTokenStore(SecretKey encKey) {
        this.encKey = encKey;
    }

    @Override
    public String create(Request request, Token token) {
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder()
            .subject(token.username)
            .audience(AUDIENCE)
            .expirationTime(Date.from(token.expiry));
        token.attributes.forEach(jwtClaimsSetBuilder::claim);

        JWEHeader jweHeader = new JWEHeader(
            JWEAlgorithm.DIR,
            EncryptionMethod.A128CBC_HS256
        );

        EncryptedJWT jwt = new EncryptedJWT(jweHeader, jwtClaimsSetBuilder.build());

        try {
            DirectEncrypter encrypter = new DirectEncrypter(encKey);
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return jwt.serialize();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            EncryptedJWT jwt = EncryptedJWT.parse(tokenId);
            DirectDecrypter decryptor = new DirectDecrypter(encKey);
            jwt.decrypt(decryptor);

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (!claims.getAudience().contains(AUDIENCE)) {
                return Optional.empty();
            }

            Instant expiry = claims.getExpirationTime().toInstant();
            String subject = claims.getSubject();
            Token token = new Token(expiry, subject);
            Set ignore = Set.of("exp", "sub", "aud");
            for (var attr : claims.getClaims().keySet()) {
                if (ignore.contains(attr)) continue;
                token.attributes.put(attr, claims.getStringClaim(attr));
            }

            return Optional.of(token);
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {

    }
}
