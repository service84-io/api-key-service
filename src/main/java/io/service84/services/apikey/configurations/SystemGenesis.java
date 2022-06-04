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

package io.service84.services.apikey.configurations;

import java.lang.reflect.Field;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import io.service84.library.keyvaluepersistence.exceptions.KeyNotFound;
import io.service84.library.keyvaluepersistence.services.KeyValueService;
import io.service84.services.apikey.errors.ServerError;
import io.service84.services.apikey.persistence.model.APIKey;
import io.service84.services.apikey.persistence.repository.APIKeyRepository;

@Service("EDFA0139-741C-44FC-B86E-8AFDAB210A05")
public class SystemGenesis {
  private static final Logger logger = LoggerFactory.getLogger(SystemGenesis.class);

  private static String GenesisDone = "GenesisDone";

  private static UUID GenesisUserID = UUID.fromString("AB43ACF4-E19A-4142-A5EA-49D69B3672A7");
  private static UUID GenesisKeyID = UUID.fromString("CD9A3ED2-9190-4B27-86CC-9EC8F5341692");
  private static String GenesisKeySecret = "GENESIS-AC0F0164-E970-4BE5-8387-8761F23EB4FF";
  private static String GenesisKeyName = "GENESIS";

  private static SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();

  private static String hashSecret(String secret) {
    return encoder.encode(secret);
  }

  @Autowired private APIKeyRepository repository;
  @Autowired private KeyValueService kvService;

  private Boolean isGenesisDone() {
    try {
      return kvService.getValue(GenesisDone, Boolean.class);
    } catch (KeyNotFound e) {
      return Boolean.FALSE;
    }
  }

  private void markGenesisDone() {
    kvService.setValue(GenesisDone, Boolean.TRUE);
  }

  private void setAPIKeyID(APIKey apiKey, UUID apiKeyIdValue) {
    try {
      Field apiKeyId = APIKey.class.getDeclaredField("id");
      apiKeyId.setAccessible(Boolean.TRUE);
      apiKeyId.set(apiKey, apiKeyIdValue);
    } catch (NoSuchFieldException
        | SecurityException
        | IllegalArgumentException
        | IllegalAccessException e) {
      throw new ServerError();
    }
  }

  @PostConstruct
  public void systemGenesis() {
    logger.debug("systemGenesis");
    if (!isGenesisDone()) {
      UUID subject = GenesisUserID;
      String secret = GenesisKeySecret;
      APIKey apiKey =
          new APIKey(subject, GenesisKeyName, secret.substring(0, 8), hashSecret(secret));
      setAPIKeyID(apiKey, GenesisKeyID);
      apiKey = repository.saveAndFlush(apiKey);
      markGenesisDone();
    }
  }
}
