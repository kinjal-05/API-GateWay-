package APIGateWayService.apigateway.security;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

//	System.out.println("[DEBUG] JwtAuthenticationFilter triggered for path: " + exchange.getRequest().getPath());
	public JwtAuthenticationFilter() {
		System.out.println("[DEBUG] JwtAuthenticationFilter initialized!");
	}

	@Autowired
	private JwtService jwtService;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange,
			org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
		System.out.println("[DEBUG] JwtAuthenticationFilter triggered for path: " + exchange.getRequest().getPath());
//		System.out.println("[DEBUG] Request Path");
		String path = exchange.getRequest().getPath().toString();
//		System.out.println("[DEBUG] Request Path: " + path);

		// ✅ Public endpoints
		if (path.startsWith("/api/auth/login") || path.startsWith("/api/auth/register")
				|| path.startsWith("/api/auth/refresh-token")) {
			System.out.println("[DEBUG] Public endpoint, skipping JWT check: " + path);
			return chain.filter(exchange);
		}

		String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		System.out.println("[DEBUG] Authorization Header: " + authHeader);

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			System.out.println("[DEBUG] No Bearer token found. Returning 401.");
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		}

		String token = authHeader.substring(7);
		System.out.println("[DEBUG] JWT Token: " + token);

		if (!jwtService.validateToken(token)) {
			System.out.println("[DEBUG] Invalid JWT token. Returning 401.");
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		}

		String username = jwtService.getUsernameFromToken(token);
//		String userId = jwtService.getUserIdFromToken(token);
		List<String> roles = jwtService.getRolesFromToken(token);
		System.out.println("[DEBUG] Username from token: " + username);
		System.out.println("[DEBUG] Roles from token: " + roles);

		// ✅ Map roles to Spring authorities (prepend ROLE_)
		var authorities = roles.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());

		System.out.println("[DEBUG] Granted Authorities: " + authorities);

		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);

		System.out.println("[DEBUG] Adding Authentication to SecurityContext");
		var exchange1 = exchange.mutate().request(r -> r.header("X-USER-ID", username) // or email
		).build();

		// ✅ Add authentication to SecurityContext
		return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
	}

	@Override
	public int getOrder() {
		return -100; // execute before Spring Security
	}
}