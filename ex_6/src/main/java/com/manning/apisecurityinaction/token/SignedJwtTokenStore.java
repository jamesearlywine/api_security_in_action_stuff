package com.manning.apisecurityinaction.token;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import spark.Request;

import java.util.Date;
import java.util.Optional;

public class SignedJwtTokenStore implements TokenStore {
    private final JWSSigner signer;
    private final JWSVerifier verifier;
    private final JWSAlgorithm algorithm;
    private final String audience;

    public SignedJwtTokenStore(
        JWSSigner jwsSigner,
        JWSVerifier jwsVerifier,
        JWSAlgorithm algorithm,
        String audience
    ) {
        this.signer = jwsSigner;
        this.verifier = jwsVerifier;
        this.algorithm = algorithm;
        this.audience = audience;
    }


    @Override
    public String create(Request request, Token token) {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(token.username)
            .audience(audience)
            .expirationTime(Date.from(token.expiry))
            .claim("attrs", token.attributes)
            .build();

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT jwt = new SignedJWT(header, claimsSet);
        try {
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        // TODO
        return Optional.empty();
    }

    @Override
    public void revoke(Request request, String tokenId) {
        // TODO
    }
}
