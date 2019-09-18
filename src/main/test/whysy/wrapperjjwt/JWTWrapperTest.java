/*
 * MIT License
 * Copyright (c) 2019 whysy
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

package whysy.wrapperjjwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JWTWrapperTest {

    private static final String API_KEY_VALUE = "5cefc9de08ee1c39100bf248:4d8b914f80cbd5297793bb6c8be044a6e7266eb7f08ac90b9c390dd27735a193";

    @Test
    public void createToken() {
        String token = JWTWrapper.generateToken(API_KEY_VALUE);

        assertNotNull("The token must be not null", token);
    }

    @Test
    public void checkToken() throws DecoderException {
        String token = JWTWrapper.generateToken(API_KEY_VALUE);

        byte[] keyBytes = Hex.decodeHex("4d8b914f80cbd5297793bb6c8be044a6e7266eb7f08ac90b9c390dd27735a193");


        Algorithm algorithm = Algorithm.HMAC256(keyBytes);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth0")
                .build(); //Reusable verifier instance
        final DecodedJWT jwt = verifier.verify(token);

        // check response
        assertNotNull("jwt must be  not null", jwt);
        assertNotNull("the token must be not null", jwt.getToken());

        final Map<String, Claim> claims = jwt.getClaims();

        // check claims
        assertNotNull("claims must be not null", claims);
        assertEquals("Invalid audience value", "/v2/admin/", claims.get("aud").asString());

        //check headers
        assertEquals("Invalid algorithm value", "HS256", jwt.getAlgorithm());
        assertEquals("Invalid type value", "JWT", jwt.getType());
        assertEquals("Invalid keyId value", "5cefc9de08ee1c39100bf248", jwt.getKeyId());

    }

}