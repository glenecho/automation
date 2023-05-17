import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class AuthCallbackController {

    @GetMapping("/auth/callback")
    public RedirectView handleCallback(@RequestParam("code") String code) {
        // Make a request to Keycloak to exchange the authorization code for an access token
        // You can use a library like HttpClient or OkHttp to make the HTTP request

        // Example using HttpClient
        HttpClient httpClient = HttpClient.newBuilder().build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://your-keycloak-server/auth/realms/your-realm/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=authorization_code&client_id=your-client-id&client_secret=your-client-secret&redirect_uri=https://example.com/auth/callback&code=" + code))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();

            // Parse the response body to extract the access token and handle it as needed

            // Redirect the user to a protected route or perform any other necessary actions
            return new RedirectView("/protected-route");
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            // Handle the error appropriately
            return new RedirectView("/error");
        }
    }
}

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.token.TokenManager;

public class KeycloakAuthCallback {

    public static void main(String[] args) {
        String keycloakBaseUrl = "https://your-keycloak-server";
        String realmName = "your-realm";
        String clientId = "your-client-id";
        String clientSecret = "your-client-secret";
        String redirectUri = "https://example.com/auth/callback";
        String authorizationCode = "authorization_code";

        // Create a Keycloak client instance
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(keycloakBaseUrl)
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("admin-password")
                .grantType(OAuth2Constants.PASSWORD)
                .build();

        // Obtain the access token using the admin credentials
        TokenManager tokenManager = keycloak.tokenManager();
        String accessToken = tokenManager.getAccessTokenString();

        // Get the realm resource
        RealmResource realmResource = keycloak.realm(realmName);

        // Exchange the authorization code for an API token
        String apiToken = realmResource
                .tokenManager()
                .grantToken(clientId, clientSecret, authorizationCode, redirectUri);

        // Use the obtained API token for API requests
        // ...

        // Log out when you no longer need the API token
        realmResource.tokenManager().logout();

        // Close the Keycloak client
        keycloak.close();
    }
}

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ProtectedRouteController {

    @Secured("ROLE_USER") // Restrict access to authenticated users with "ROLE_USER" authority
    @GetMapping("/protected-route")
    public String protectedRoute() {
        // Handle the logic for the protected route
        return "protected-page";
    }
}

<dependencies>
    <!-- Other dependencies -->
    
    <!-- Keycloak dependencies -->
    <dependency>
        <groupId>org.keycloak</groupId>
        <artifactId>keycloak-core</artifactId>
        <version>15.0.2</version>
    </dependency>
    <dependency>
        <groupId>org.keycloak</groupId>
        <artifactId>keycloak-adapter-core</artifactId>
        <version>15.0.2</version>
    </dependency>
    <dependency>
        <groupId>org.keycloak</groupId>
        <artifactId>keycloak-servlet-adapter</artifactId>
        <version>15.0.2</version>
    </dependency>
</dependencies>

