package com.manning.apisecurityinaction.token;

import org.json.JSONException;
import org.json.JSONObject;
import spark.Request;

import java.time.Instant;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JsonTokenStore implements TokenStore {
    @Override
    public String create(Request request, Token token) {
        JSONObject json = new JSONObject();

        json.put("sub", token.username);
        json.put("exp", token.expiry.getEpochSecond());
        json.put("attrs", token.attributes);

        byte[] jsonBytes = json.toString().getBytes(UTF_8);

        return Base64url.encode(jsonBytes);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {

        try {
            byte[] decoded = Base64url.decode(tokenId);

            JSONObject json = new JSONObject(new String(decoded, UTF_8));
            Instant expiry = Instant.ofEpochSecond(json.getInt("exp"));
            String username = json.getString("sub");

            Token token = new Token(expiry, username);
            JSONObject attrs = json.getJSONObject("attrs");
            for (var key : attrs.keySet()) {
                token.attributes.put(key, attrs.getString(key));
            }

            return Optional.of(token);
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {
        // TODO
    }
}
