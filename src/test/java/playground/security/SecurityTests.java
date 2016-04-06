package playground.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.web.client.reactive.WebResponseExtractors.response;
import static reactive.client.SecurityPostProcessors.httpBasic;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Map;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.HttpHandler;

import playground.Application;
import reactive.client.ExtendedDefaultHttpRequestBuilder;
import reactive.client.RequestPostProcessor;
import reactor.core.publisher.Mono;

@SuppressWarnings("rawtypes")
public class SecurityTests extends AbstractHttpHandlerIntegrationTests {

	private AnnotationConfigApplicationContext wac;

	@After
	public void closeWac() {
		try {
			wac.close();
		}catch(Exception ignore) {}
	}

	@Override
	protected HttpHandler createHttpHandler() throws IOException {
		return Application.createHttpHandler();
	}


	@Test
	public void basicWorks() throws Exception {
		Mono<ResponseEntity<Map>> response = this.webClient
				.perform(peopleRequest().with(robsCredentials()))
				.extract(response(Map.class));

		assertThat(response.get().getStatusCode()).isEqualTo(HttpStatus.OK);
	}

	private RequestPostProcessor robsCredentials() {
		return httpBasic("rob","rob");
	}

	private ExtendedDefaultHttpRequestBuilder peopleRequest() {
		return new ExtendedDefaultHttpRequestBuilder(HttpMethod.GET, "http://localhost:" + port + "/people");
	}

	private ExtendedDefaultHttpRequestBuilder meRequest() {
		return new ExtendedDefaultHttpRequestBuilder(HttpMethod.GET, "http://localhost:" + port + "/me");
	}

	private String base64Encode(String value) {
		return Base64.getEncoder().encodeToString(value.getBytes(Charset.defaultCharset()));
	}
}
