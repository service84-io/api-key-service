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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component("88A4D9E8-FEE3-4DA3-B597-58DAD655280A")
public class ApplicationStartup implements ApplicationListener<ApplicationReadyEvent> {
  private static final Logger logger = LoggerFactory.getLogger(ApplicationStartup.class);

  /**
   * This event is executed as late as conceivably possible to indicate that the application is
   * ready to service requests.
   */
  @Override
  public void onApplicationEvent(final ApplicationReadyEvent event) {
    logger.info("------------------------------------------");
    logger.info("Initializing application startup processes");
    logger.info("------------------------------------------");

    logger.info("------------------------------------------");
    logger.info("Application startup completed");
    logger.info("------------------------------------------");
  }
}
