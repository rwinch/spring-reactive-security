/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package playground.app;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.reactivestreams.Publisher;
import org.springframework.stereotype.Repository;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 */
@Repository
public class StubPersonRepository implements ReactiveRepository<Person> {
	List<Person> people = new ArrayList<>(Arrays.asList(new Person("1", "first", "last")));

	@Override
	public Mono<Void> insert(Publisher<Person> personStream) {
		return Flux.from(personStream).doOnNext(people::add).then();
	}

	@Override
	public Flux<Person> list() {
		return Flux.fromIterable(people);
	}

	@Override
	public Mono<Person> findById(String id) {
		return null;
	}

}
