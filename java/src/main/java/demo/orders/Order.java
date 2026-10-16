package demo.orders;

import java.util.List;

public record Order(String id, String customerId, List<OrderItem> items, OrderStatus status) {

    public record OrderItem(String sku, int quantity) {
    }

    public record NewOrder(String customerId, List<OrderItem> items) {
    }

    public enum OrderStatus {
        PENDING,
        PAID,
        SHIPPED
    }
}
