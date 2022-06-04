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

package io.service84.services.apikey.services;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import io.service84.library.standardpersistence.services.PaginationTranslator;
import io.service84.services.apikey.dto.APIKeyDTO;
import io.service84.services.apikey.dto.APIKeyDetailsDTO;
import io.service84.services.apikey.dto.APIKeyPageDTO;
import io.service84.services.apikey.dto.MetadataDTO;
import io.service84.services.apikey.persistence.model.APIKey;
import io.service84.services.apikey.services.APIKeyService.APIKeyDetails;

@Service("29E5341A-BC89-4294-BC3F-C457ED8BC15E")
public class Translator extends PaginationTranslator {
  private static final Logger logger = LoggerFactory.getLogger(Translator.class);

  public static class MetadataPDSDTO extends MetadataDTO implements CursorPaginationDataStandard {}

  public APIKeyDTO translate(APIKey entity) {
    logger.debug("translate");
    if (entity == null) {
      return null;
    }

    APIKeyDTO dto = new APIKeyDTO();
    dto.setId(entity.getId());
    dto.setSubject(entity.getSubject());
    dto.setName(entity.getName());
    dto.setSecretPrefix(entity.getSecretPrefix());
    return dto;
  }

  public ResponseEntity<APIKeyDTO> translate(APIKey entity, HttpStatus status) {
    logger.debug("translate");
    return new ResponseEntity<>(translate(entity), status);
  }

  public APIKeyDetailsDTO translate(APIKeyDetails entity) {
    logger.debug("translate");
    if (entity == null) {
      return null;
    }

    APIKey apiKey = entity.apiKey;

    if (apiKey == null) {
      return null;
    }

    APIKeyDetailsDTO dto = new APIKeyDetailsDTO();
    dto.setId(apiKey.getId());
    dto.setName(apiKey.getName());
    dto.setSecretPrefix(apiKey.getSecretPrefix());
    dto.setSecret(entity.secret);
    return dto;
  }

  public ResponseEntity<APIKeyDetailsDTO> translate(APIKeyDetails entity, HttpStatus status) {
    logger.debug("translate");
    return new ResponseEntity<>(translate(entity), status);
  }

  public ResponseEntity<Void> translate(HttpStatus status) {
    logger.debug("translate");
    return new ResponseEntity<>(status);
  }

  public ResponseEntity<APIKeyDetailsDTO> translateAPIKeyDetails(
      APIKeyDetails entity, HttpStatus status) {
    logger.debug("translateAPIKeyDetails");
    return new ResponseEntity<>(translate(entity), status);
  }

  public APIKeyPageDTO translateAPIKeyPage(Page<APIKey> page) {
    logger.debug("translateAPIKeyPage");
    if (page == null) {
      return null;
    }

    List<APIKeyDTO> content =
        page.getContent().stream().map(e -> translate(e)).collect(Collectors.toList());
    return new APIKeyPageDTO()
        .metadata(cursorMetadata(page, MetadataPDSDTO.class))
        .content(content);
  }

  public ResponseEntity<APIKeyPageDTO> translateAPIKeyPage(Page<APIKey> page, HttpStatus status) {
    logger.debug("translateAPIKeyPage");
    return new ResponseEntity<>(translateAPIKeyPage(page), status);
  }
}
