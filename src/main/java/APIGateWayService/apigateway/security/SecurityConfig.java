package APIGateWayService.apigateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

@Configuration
public class SecurityConfig {

	private final JwtService jwtService;

	public SecurityConfig(JwtService jwtService) {
		this.jwtService = jwtService;
	}

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		// Custom JWT filter
		AuthenticationWebFilter jwtAuthFilter = new AuthenticationWebFilter(jwtReactiveAuthenticationManager());
		jwtAuthFilter.setServerAuthenticationConverter(new JwtServerAuthenticationConverter(jwtService));

		http.csrf().disable().authorizeExchange(exchanges -> exchanges
				.pathMatchers("/api/auth/register", "/api/auth/login", "/api/auth/refresh-token", "/notifications/**")
				.permitAll().pathMatchers("/api/auth/me/**").authenticated().pathMatchers("/api/auth/users/**")
				.hasRole("ADMIN")
				.pathMatchers("/api/categories/v1/creatCategory/**", "/api/categories/v1/getById/**",
						"/api/categories/v1/updateById/**", "/api/categories/v1/deleteById/**",
						"/api/products/addProducts/**", "/api/products/updateById/**", "/api/products/deleteById/**",
						"/api/products/getProductById/**", "/api/product-images/v1/products/**",
						"/api/product-images/v1/updateimage/**", "/api/product-images/v1/deleteimage/**")
				.hasRole("ADMIN").pathMatchers("/api/categories/v1/getAllCategories/**").authenticated().anyExchange()
				.authenticated()).addFilterAt(jwtAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION).httpBasic()
				.disable();

		return http.build();
	}

	@Bean
	public ReactiveAuthenticationManager jwtReactiveAuthenticationManager() {
		return new JwtReactiveAuthenticationManager(jwtService);
	}
}