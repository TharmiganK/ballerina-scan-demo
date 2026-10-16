import ballerina/http;
import ballerina/uuid;

configurable int port = 9090;

enum OrderStatus {
    PENDING,
    PAID,
    SHIPPED
}

type OrderItem record {
    string sku;
    int quantity;
};

type NewOrder record {
    string customerId;
    OrderItem[] items;
};

type Order record {|
    readonly string id;
    string customerId;
    OrderItem[] items;
    OrderStatus status;
|};

isolated table<Order> key(id) orders = table [];

// Vulnerable: ballerina/http:2 - any origin may call the API with the user's credentials.
@http:ServiceConfig {
    cors: {
        allowOrigins: ["*"],
        allowCredentials: true
    }
}
service /orders on new http:Listener(port) {

    resource function get .() returns Order[] {
        lock {
            return orders.toArray().clone();
        }
    }

    resource function get [string id]() returns Order|http:NotFound {
        lock {
            Order? 'order = orders[id];
            if 'order is () {
                return http:NOT_FOUND;
            }
            return 'order.clone();
        }
    }

    resource function post .(NewOrder newOrder) returns http:Created {
        Order 'order = {id: uuid:createType4AsString(), customerId: newOrder.customerId, items: newOrder.items, status: PENDING};
        lock {
            orders.add('order.clone());
        }
        return {body: 'order};
    }

    // Vulnerable: ballerina/http:4 - the client chooses where the browser is sent after checkout.
    resource function get checkout/[string returnUrl]() returns http:TemporaryRedirect {
        return {
            headers: {
                "Location": returnUrl
            }
        };
    }
}

// Vulnerable: ballerina/http:1 - the legacy sync endpoint answers every HTTP method, including unsafe ones.
service /legacy on new http:Listener(9095) {

    resource function default sync() returns string {
        return "synced";
    }
}
