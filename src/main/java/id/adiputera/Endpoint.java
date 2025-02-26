package id.adiputera;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;

/**
 * Azure Functions with HTTP Trigger.
 *
 * @author Yusuf F. Adiputera
 */
public class Endpoint {

    /**
     * This function listens at endpoint "/api/endpoint".
     */
    @FunctionName("endpoint")
    public HttpResponseMessage run(
            @HttpTrigger(
                    name = "req",
                    methods = {HttpMethod.GET, HttpMethod.POST},
                    authLevel = AuthorizationLevel.ANONYMOUS)
            HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        final String authorization = request.getHeaders().get("authorization");
        final Map<String, String> response = new HashMap<>();
        if (Util.stringIsNotEmpty(authorization) && authorization.startsWith("Bearer ")) {
            final String secret = System.getenv("jwt_secret_key");
            final String token = authorization.split(" ")[1];
            try {
                final Algorithm algorithm = Algorithm.HMAC256(secret);
                final JWTVerifier verifier = JWT.require(algorithm)
                        .withIssuer("adiputera")
                        .build();

                final DecodedJWT decodedJWT = verifier.verify(token);
                final String clientId = decodedJWT.getSubject();
                if (Util.stringIsNotEmpty(clientId) && Util.stringIsNotEmpty(System.getenv(clientId))) {
                    response.put("message", "You have access to this endpoint");
                    return request.createResponseBuilder(HttpStatus.OK)
                            .body(response)
                            .header("Content-Type", "application/json")
                            .build();
                }
            } catch (Exception e) {
                context.getLogger().log(Level.WARNING, String.format("Invalid token: %s", e.getMessage()));
            }
        }
        response.put("error", "Unauthorized");
        return request.createResponseBuilder(HttpStatus.FORBIDDEN)
                .body(response)
                .header("Content-Type", "application/json")
                .build();
    }
}
