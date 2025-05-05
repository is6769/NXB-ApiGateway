package org.example.apigateway;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiGatewayApplication.class, args);
	}

	@Bean
	public ApplicationRunner filterDebug(ApplicationContext ctx) {
		return args -> {
			System.out.println("REGISTERED FILTERS: " +
					ctx.getBeansOfType(GatewayFilterFactory.class).keySet());
		};
	}

}
