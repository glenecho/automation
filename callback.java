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
