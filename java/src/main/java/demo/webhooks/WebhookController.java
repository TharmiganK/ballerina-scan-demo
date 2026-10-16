package demo.webhooks;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

@RestController
@RequestMapping("/webhooks")
public class WebhookController {

    private static final Logger log = LoggerFactory.getLogger(WebhookController.class);

    private final RestClient restClient = RestClient.create();
    private final String subscriberBaseUrl;
    private final String relayApiKey;

    public WebhookController(@Value("${subscriber.base-url}") String subscriberBaseUrl,
                             @Value("${relay.api-key}") String relayApiKey) {
        this.subscriberBaseUrl = subscriberBaseUrl;
        this.relayApiKey = relayApiKey;
    }

    public record WebhookEvent(String type, JsonNode data) {
    }

    @PostMapping("/{target}")
    public JsonNode relay(@PathVariable String target, @RequestBody WebhookEvent event) {
        // Vulnerable: ballerina/log:1 (CWE-532) - the API key is written to the log.
        log.debug("Relaying {} to {} with key {}", event.type(), target, relayApiKey);
        // Vulnerable: ballerina/http:3 (CWE-918) - the caller picks the internal path the relay calls (SSRF).
        JsonNode ack = restClient.get()
                .uri(subscriberBaseUrl + "/hooks/" + target)
                .retrieve()
                .body(JsonNode.class);
        return ack;
    }
}
