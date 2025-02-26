package id.adiputera;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Azure Functions with HTTP Trigger.
 *
 * @author Yusuf F. Adiputera
 */
public class Auth {

    /**
     * This function listens at endpoint "/api/auth"
     */
    @FunctionName("auth")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req",
                    methods = {HttpMethod.POST},
                    authLevel = AuthorizationLevel.ANONYMOUS)
            HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        final String secret = System.getenv("jwt_secret_key");
        final String jwtExpiresIn = System.getenv("jwt_expire_time");
        final String clientId = request.getQueryParameters().get("client_id");
        final String clientSecret = request.getQueryParameters().get("client_secret");
        final String savedClientSecret = System.getenv(clientId);
        final Map<String, String> response = new HashMap<>();
        if (Util.stringNotEmpty(secret) && Util.stringNotEmpty(clientId) && Util.stringNotEmpty(jwtExpiresIn) &&
                Util.stringNotEmpty(clientSecret) && clientSecret.equalsIgnoreCase(savedClientSecret)) {
            Instant expirationTime = Instant.now().plusSeconds(Integer.parseInt(jwtExpiresIn));

            // Create JWT
            String token = JWT.create()
                    .withIssuer("adiputera")
                    .withSubject(clientId)
                    .withIssuedAt(new Date()) // Issue date
                    .withExpiresAt(Date.from(expirationTime)) // Expiration date
                    .sign(Algorithm.HMAC256(secret)); // Sign with secret key

            // Parse query parameter
            response.put("access_token", token);
            response.put("expires_in", jwtExpiresIn);
            response.put("type", "Bearer");

            return request.createResponseBuilder(HttpStatus.OK)
                    .body(response)
                    .header("Content-Type", "application/json")
                    .build();
        }
        response.put("error", "invalid credentials");
        return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                .body(response)
                .header("Content-Type", "application/json")
                .build();
    }
}
