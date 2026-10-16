package demo.orders;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LegacyController {

    // Vulnerable: ballerina/http:1 (CWE-352) - the legacy sync endpoint answers every HTTP method, including unsafe ones.
    @RequestMapping("/legacy/sync")
    public String sync() {
        return "synced";
    }
}
