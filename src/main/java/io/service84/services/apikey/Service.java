/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.service84.services.apikey;

import java.util.TimeZone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
@ComponentScan({"io.service84"})
@EnableJpaRepositories({"io.service84"})
@EntityScan({"io.service84"})
@EnableSwagger2
@PropertySources({@PropertySource("classpath:application.properties")})
public class Service {
  private static final Logger logger = LoggerFactory.getLogger(Service.class);

  public static void main(String[] args) {
    logger.debug("main");
    setUTCTimeZone();
    SpringApplication.run(Service.class, args);
  }

  private static void setUTCTimeZone() {
    logger.debug("setUTCTimeZone");
    TimeZone UTC = TimeZone.getTimeZone("UTC");
    TimeZone current = TimeZone.getDefault();

    if (!UTC.equals(current)) {
      logger.info("Changing Default TimeZone from {} to {}", current, UTC);
    }

    TimeZone.setDefault(UTC);
  }
}
