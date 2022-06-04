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

package io.service84.services.apikey.api.rest;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import io.service84.library.authutils.services.AuthenticationService;
import io.service84.library.exceptionalresult.models.ExceptionalException;
import io.service84.library.standardservice.services.RequestService;
import io.service84.services.apikey.api.ApiKeyApiDelegate;
import io.service84.services.apikey.api.rest.exceptionalresults.AuthenticationFailed;
import io.service84.services.apikey.api.rest.exceptionalresults.InsufficientPermissionResult;
import io.service84.services.apikey.api.rest.exceptionalresults.InternalServerError;
import io.service84.services.apikey.api.rest.exceptionalresults.NotFound;
import io.service84.services.apikey.dto.APIKeyAuthenticationDTO;
import io.service84.services.apikey.dto.APIKeyDTO;
import io.service84.services.apikey.dto.APIKeyDetailsDTO;
import io.service84.services.apikey.dto.APIKeyPageDTO;
import io.service84.services.apikey.dto.APIKeyRequestDTO;
import io.service84.services.apikey.exceptions.EntityNotFound;
import io.service84.services.apikey.exceptions.InsufficientPermission;
import io.service84.services.apikey.persistence.model.APIKey;
import io.service84.services.apikey.services.APIKeyService;
import io.service84.services.apikey.services.APIKeyService.APIKeyDetails;
import io.service84.services.apikey.services.Translator;

@Service("C07A331E-912D-4B7D-939D-ACA3E60FA543")
public class ApiKeyDelegate implements ApiKeyApiDelegate {
  private static Logger logger = LoggerFactory.getLogger(ApiKeyDelegate.class);

  @Autowired private APIKeyService apiKeyService;
  @Autowired private AuthenticationService authenticationService;
  @Autowired private RequestService requestService;
  @Autowired private Translator translator;

  @Override
  public ResponseEntity<APIKeyDTO> authenticateApiKey(
      APIKeyAuthenticationDTO body, String authentication) {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      APIKey apiKey = apiKeyService.authenticatedAPIKey(body.getId(), body.getSecret());
      ResponseEntity<APIKeyDTO> result = translator.translate(apiKey, HttpStatus.OK);
      logger.info("OK");
      return result;
    } catch (EntityNotFound e) {
      logger.info("Authentication Failed");
      throw new AuthenticationFailed();
    } catch (InsufficientPermission e) {
      logger.info("Insufficient Permission");
      throw new InsufficientPermissionResult();
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }

  @Override
  public ResponseEntity<APIKeyDetailsDTO> requestApiKey(
      APIKeyRequestDTO body, String authentication) {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      APIKeyDetails apiKeyDetails = apiKeyService.requestAPIKey(body.getName());
      ResponseEntity<APIKeyDetailsDTO> result = translator.translate(apiKeyDetails, HttpStatus.OK);
      logger.info("OK");
      return result;
    } catch (InsufficientPermission e) {
      logger.info("Insufficient Permission");
      throw new InsufficientPermissionResult();
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }

  @Override
  public ResponseEntity<APIKeyDTO> retrieveApiKey(UUID id, String authentication) {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      APIKey apiKey = apiKeyService.retrieveApiKey(id);
      ResponseEntity<APIKeyDTO> result = translator.translate(apiKey, HttpStatus.OK);
      logger.info("OK");
      return result;
    } catch (EntityNotFound e) {
      logger.info("Entity Not Found");
      throw new NotFound();
    } catch (InsufficientPermission e) {
      logger.info("Insufficient Permission");
      throw new InsufficientPermissionResult();
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }

  @Override
  public ResponseEntity<APIKeyPageDTO> retrieveApiKeys(
      String authentication, String pageIndex, Integer pageSize) {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      Pageable pageable = translator.getPageable(pageIndex, pageSize);
      Page<APIKey> apiKeyPage = apiKeyService.retrieveApiKeys(pageable);
      ResponseEntity<APIKeyPageDTO> result =
          translator.translateAPIKeyPage(apiKeyPage, HttpStatus.OK);
      logger.info("OK");
      return result;
    } catch (InsufficientPermission e) {
      logger.info("Insufficient Permission");
      throw new InsufficientPermissionResult();
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }

  @Override
  public ResponseEntity<Void> revokeApiKey(UUID id, String authentication) {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      apiKeyService.revokeApiKey(id);
      ResponseEntity<Void> result = translator.translate(HttpStatus.NO_CONTENT);
      logger.info("No Content");
      return result;
    } catch (EntityNotFound e) {
      logger.info("Entity Not Found");
      throw new NotFound();
    } catch (InsufficientPermission e) {
      logger.info("Insufficient Permission");
      throw new InsufficientPermissionResult();
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }
}
