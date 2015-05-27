package org.wellspring.example.angular.backend;

import javax.servlet.Filter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.wellspring.config.jackson.JacksonConfig;
import org.wellspring.crud.util.CrudPackageConstants;
import org.wellspring.example.angular.backend.util.PackageConstants;

import com.planetj.servlet.filter.compression.CompressingFilter;

@EnableJpaRepositories
@EnableAutoConfiguration
@PropertySource("application.properties")
@Import(JacksonConfig.class)
@ComponentScan(basePackages = { PackageConstants.BASE_PACKAGE, CrudPackageConstants.CONTROLLER_PACKAGE })
public class Application {

	public static void main(String[] args) {
		String webPort = System.getenv("PORT");
		if (webPort == null || webPort.isEmpty()) {
			webPort = "8080";
		}
		System.setProperty("server.port", webPort);
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public Filter characterEncodingFilter() {
		CharacterEncodingFilter characterEncodingFilter = new CharacterEncodingFilter();
		characterEncodingFilter.setEncoding("UTF-8");
		characterEncodingFilter.setForceEncoding(true);
		return characterEncodingFilter;
	}
	
	@Bean
	public Filter compressingFilter() {
	    CompressingFilter compressingFilter = new CompressingFilter();
	    return compressingFilter;
	}

}