package seol.ecommerce.apigateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class CustomFilter extends AbstractGatewayFilterFactory<CustomFilter.Config> {

	public CustomFilter() {
		super(Config.class);
	}

	public static class Config {
		// Configuration 정보를 넣을 수 있다.
	}

	@Override
	public GatewayFilter apply(Config config) {
		// Custom Pre Filter
		return (exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest();
			ServerHttpResponse response = exchange.getResponse();

			log.info("Custom PRE filter: request id -> {}", request.getId());

			// Custom PostFilter
			return chain.filter(exchange).then(Mono.fromRunnable(() -> {
				log.info("Custom POST filter: response code -> {}", response.getStatusCode());
			}));
		};
	}
}
