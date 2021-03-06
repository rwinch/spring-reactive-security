package playground.itests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.web.client.reactive.ResponseExtractors.response;
import static org.springframework.security.web.client.reactive.SecurityClientWebRequestPostProcessors.httpBasic;
import static org.springframework.web.client.reactive.ClientWebRequestBuilders.*;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Map;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.web.client.reactive.ClientWebRequestPostProcessor;
import org.springframework.web.client.reactive.DefaultClientWebRequestBuilder;

import playground.app.Application;
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
	public void basicRequired() throws Exception {
		Mono<ResponseEntity<String>> response = this.webClient
				.perform(peopleRequest())
				.extract(response(String.class));

		assertThat(response.block().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void basicWorks() throws Exception {
		Mono<ResponseEntity<Map>> response = this.webClient
				.perform(peopleRequest().apply(robsCredentials()))
				.extract(response(Map.class));

		assertThat(response.block().getStatusCode()).isEqualTo(HttpStatus.OK);
	}

	@Test
	public void authorizationAdmin401() throws Exception {
		Mono<ResponseEntity<Map>> response = this.webClient
				.perform(adminRequest().apply(robsCredentials()))
				.extract(response(Map.class));

		assertThat(response.block().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void authorizationAdmin200() throws Exception {
		Mono<ResponseEntity<Map>> response = this.webClient
				.perform(adminRequest().apply(adminCredentials()))
				.extract(response(Map.class));

		assertThat(response.block().getStatusCode()).isEqualTo(HttpStatus.OK);
	}

	@Test
	public void basicMissingUser401() throws Exception {
		Mono<ResponseEntity<String>> response = this.webClient
				.perform(peopleRequest().apply(httpBasic("missing-user","rob")))
				.extract(response(String.class));
	
		assertThat(response.block().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void basicInvalidPassword401() throws Exception {
		Mono<ResponseEntity<String>> response = this.webClient
				.perform(peopleRequest().apply(httpBasic("rob","invalid")))
				.extract(response(String.class));

		assertThat(response.block().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void basicInvalidParts401() throws Exception {
		Mono<ResponseEntity<String>> response = this.webClient
				.perform(peopleRequest().header("Authorization", "Basic " + base64Encode("no colon")))
				.extract(response(String.class));

		assertThat(response.block().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void sessionWorks() throws Exception {
		Mono<ResponseEntity<Map>> response = this.webClient
				.perform(peopleRequest().apply(robsCredentials()))
				.extract(response(Map.class));

		String session = response.block().getHeaders().getFirst("Set-Cookie");

		response = this.webClient
				.perform(peopleRequest().header("Cookie", session))
				.extract(response(Map.class));

		assertThat(response.block().getStatusCode()).isEqualTo(HttpStatus.OK);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void me() throws Exception {
		Mono<ResponseEntity<Map>> response = this.webClient
				.perform(meRequest().apply(robsCredentials()))
				.extract(response(Map.class));

		assertThat(response.block().getBody()).hasSize(1).containsEntry("username", "rob");
	}
	
	private ClientWebRequestPostProcessor robsCredentials() {
		return httpBasic("rob","rob");
	}

	private ClientWebRequestPostProcessor adminCredentials() {
		return httpBasic("admin","admin");
	}

	private DefaultClientWebRequestBuilder adminRequest() {
		return get("http://localhost:{port}/admin", port);
	}

	private DefaultClientWebRequestBuilder peopleRequest() {
		return get("http://localhost:{port}/people", port);
	}

	private DefaultClientWebRequestBuilder meRequest() {
		return get("http://localhost:{port}/me",port);
	}

	private String base64Encode(String value) {
		return Base64.getEncoder().encodeToString(value.getBytes(Charset.defaultCharset()));
	}
}
