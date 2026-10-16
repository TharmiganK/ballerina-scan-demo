package demo.orders;

import demo.orders.Order.NewOrder;
import demo.orders.Order.OrderStatus;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// Vulnerable: ballerina/http:2 (CWE-942) - any origin may call the API with the user's credentials.
@CrossOrigin(originPatterns = "*", allowCredentials = "true")
@RestController
@RequestMapping("/orders")
public class OrdersController {

    private final Map<String, Order> orders = new ConcurrentHashMap<>();

    @GetMapping
    public List<Order> listOrders() {
        return List.copyOf(orders.values());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Order> getOrder(@PathVariable String id) {
        Order order = orders.get(id);
        return order == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(order);
    }

    @PostMapping
    public ResponseEntity<Order> createOrder(@RequestBody NewOrder newOrder) {
        Order order = new Order(UUID.randomUUID().toString(), newOrder.customerId(), newOrder.items(),
                OrderStatus.PENDING);
        orders.put(order.id(), order);
        return ResponseEntity.status(HttpStatus.CREATED).body(order);
    }

    // Vulnerable: ballerina/http:4 (CWE-601) - the client chooses where the browser is sent after checkout.
    @GetMapping("/checkout/{returnUrl}")
    public void checkout(@PathVariable String returnUrl, HttpServletResponse response) throws IOException {
        response.sendRedirect(returnUrl);
    }
}
