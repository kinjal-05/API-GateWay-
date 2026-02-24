package APIGateWayService.apigateway.security;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Converts HTTP requests with Bearer tokens into Authentication objects.
 */
public class JwtServerAuthenticationConverter implements ServerAuthenticationConverter {

	private final JwtService jwtService;

	public JwtServerAuthenticationConverter(JwtService jwtService) {
		this.jwtService = jwtService;
	}

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			String token = authHeader.substring(7);
			return Mono.just(
					new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(token, token));
		}

		return Mono.empty();
	}
}