package com.manning.apisecurityinaction.token;

import software.pando.crypto.nacl.SecretBox;
import spark.Request;

import java.security.Key;
import java.util.Optional;

public class EncryptedTokenStore implements TokenStore {
    private final TokenStore delegateTokenStore;
    private final Key encryptionKey;

    public EncryptedTokenStore(TokenStore tokenStore, Key encryptionKey) {
        this.delegateTokenStore = tokenStore;
        this.encryptionKey = encryptionKey;
    }

    @Override
    public String create(Request request, Token token) {
        String tokenId = delegateTokenStore.create(request, token);

        return SecretBox.encrypt(encryptionKey, tokenId).toString();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
         SecretBox secretBox = SecretBox.fromString(tokenId);
         String originalTokenId = secretBox.decryptToString(encryptionKey);

         return delegateTokenStore.read(request, originalTokenId);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        SecretBox secretBox = SecretBox.fromString(tokenId);
        String originalTokenId = secretBox.decryptToString(encryptionKey);

        delegateTokenStore.revoke(request, originalTokenId);
    }
}
