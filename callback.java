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

<dependencies>
    <!-- Other dependencies -->
    
    <!-- Keycloak client dependency -->
    <dependency>
        <groupId>org.keycloak</groupId>
        <artifactId>keycloak-admin-client</artifactId>
        <version>15.0.2</version>
    </dependency>
</dependencies>


import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

public class KeycloakClientLoginExample {

    public static void main(String[] args) {
        String keycloakBaseUrl = "https://your-keycloak-server";
        String realmName = "your-realm";
        String clientId = "your-client-id";
        String clientSecret = "your-client-secret";
        String username = "your-username";
        String password = "your-password";

        // Create a Keycloak client instance
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(keycloakBaseUrl)
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("admin-password")
                .build();

        // Obtain the access token using the admin credentials
        TokenManager tokenManager = keycloak.tokenManager();
        String accessToken = tokenManager.getAccessTokenString();

        // Get the realm resource for the desired realm
        RealmResource realmResource = keycloak.realm(realmName);

        // Create a new user representation
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEnabled(true);

        // Set the user's password
        CredentialRepresentation credentials = new CredentialRepresentation();
        credentials.setType(CredentialRepresentation.PASSWORD);
        credentials.setValue(password);
        user.setCredentials(List.of(credentials));

        // Register the new user
        realmResource.users().create(user);

        // Perform client login using the new user's credentials
        AccessTokenResponse tokenResponse = tokenManager
                .grantToken(realmName, clientId, username, password);

        // Obtain the access token from the response
        String userAccessToken = tokenResponse.getToken();

        // Use the obtained access token for further operations
        // ...

        // Close the Keycloak client
        keycloak.close();
    }
}

If you want to use RedirectView in Spring Boot but prevent it from actually redirecting, you can achieve that by subclassing RedirectView and overriding the sendRedirect method. Here's an example:

java
Copy code
import org.springframework.web.servlet.view.RedirectView;

public class CustomRedirectView extends RedirectView {
    
    public CustomRedirectView(String url) {
        super(url);
    }
    
    @Override
    protected void sendRedirect(
            HttpServletRequest request, HttpServletResponse response, String targetUrl, boolean http10Compatible)
            throws IOException {

        // Do nothing, effectively disabling the redirect
    }
}
In the above code, we create a custom class CustomRedirectView that extends RedirectView. We override the sendRedirect method, which is responsible for performing the actual redirect.

By doing nothing inside this method, we effectively disable the redirect. The request will proceed as if it were a normal request, without any redirection taking place.

To use this custom redirect view in your Spring Boot application, you can simply create an instance of CustomRedirectView instead of using RedirectView. Here's an example controller method that returns the custom redirect view:

java
Copy code
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class MyController {
    
    @GetMapping("/redirect")
    public ModelAndView redirect() {
        CustomRedirectView customRedirectView = new CustomRedirectView("/target");
        return new ModelAndView(customRedirectView);
    }
}
In the above example, when the /redirect endpoint is accessed, the redirect() method is executed. It creates an instance of CustomRedirectView with the target URL "/target" and returns a ModelAndView with this custom redirect view.

Now, when a user accesses /redirect, instead of being redirected to /target, the request will continue as a normal request without any redirection occurring.


package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// Set connection options
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")

	// Connect to MongoDB
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Ping the MongoDB server to verify the connection
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	// Disconnect from MongoDB
	err = client.Disconnect(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Disconnected from MongoDB!")
}
