/*
 * MIT License
 * Copyright (c) 2020 whysy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.whysy.wrapperjjwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * A very simple wrapper to generate JWT Token for Ghost content API
 */
public class JWTWrapper {

    private static final Logger LOGGER = Logger.getLogger(JWTWrapper.class.getName());
    private static final String API_KEY_SPLIT_CHARACTER = ":";
    private static final int TOKEN_VALIDITY = 5;

    /**
     * Generate a JWT Token from the given key parameter. The token validity is 5 minutes
     *
     * @param apiKey API key obtained by creating a new Custom Integration under the Integrations screen in Ghost Admin
     * @return the JWT Token, in case of error return NULL
     */
    public static String generateToken(String apiKey) {
        String token = null;

        try {
            // Extract keyId and secret
            String[] secret = extractSecret(apiKey);

            // Generate algorithm from secret
            byte[] keyBytes = Hex.decodeHex(secret[1]);
            Algorithm algorithm = Algorithm.HMAC256(keyBytes);

            // Create claims
            Map<String, Object> headerClaims = new HashMap<>();
            headerClaims.put("typ", "JWT");
            headerClaims.put("alg", "HS256");
            headerClaims.put("kid", secret[0]);

            // Create token
            token = JWT.create()
                    .withHeader(headerClaims)
                    .withIssuer("auth0")
                    .withIssuedAt(new DateTime().toDate())
                    .withExpiresAt(new DateTime().plusMinutes(TOKEN_VALIDITY).toDate())
                    .withAudience("/v2/admin/")
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            LOGGER.warning("Invalid Signing configuration / Couldn't convert Claims : " + exception.getMessage());
        } catch (DecoderException exception) {
            LOGGER.warning("Unable to decode secret : " + exception.getMessage());
        } catch (IllegalArgumentException exception) {
            LOGGER.warning("Invalid inout data : " + exception.getMessage());
        }

        return token;

    }

    /**
     * Extract KeyId and secret from the given Admin key
     *
     * @param apiKey API key obtained by creating a new Custom Integration under the Integrations screen in Ghost Admin
     * @return
     */
    private static String[] extractSecret(String apiKey) {
        if (StringUtils.isNotEmpty(apiKey) && apiKey.contains(API_KEY_SPLIT_CHARACTER)) {
            return apiKey.split(API_KEY_SPLIT_CHARACTER);
        } else {
            throw new IllegalArgumentException("The Admin key must be not null and must contain two part separate by " + "'" + API_KEY_SPLIT_CHARACTER + "'");
        }
    }
}
