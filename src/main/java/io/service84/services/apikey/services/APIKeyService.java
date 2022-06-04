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

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import io.service84.library.authutils.services.AuthenticationService;
import io.service84.services.apikey.exceptions.EntityNotFound;
import io.service84.services.apikey.exceptions.InsufficientPermission;
import io.service84.services.apikey.persistence.model.APIKey;
import io.service84.services.apikey.persistence.repository.APIKeyRepository;

@Service("56C22312-C5E6-4735-BE09-C56BAFE98F04")
public class APIKeyService {
  private static final Logger logger = LoggerFactory.getLogger(APIKeyService.class);

  public static class APIKeyDetails {
    public APIKey apiKey;
    public String secret;
  }

  private static String AuthenticateAnyAPIKey = "authentication:authenticate_any_api_key";
  private static String RequestSelfAPIKey = "authentication:request_self_api_key";
  private static String RetrieveAnyAPIKey = "authentication:retrieve_any_api_key";
  private static String RetrieveSelfAPIKey = "authentication:retrieve_self_api_key";
  private static String RetrieveAnyAPIKeys = "authentication:retrieve_any_api_keys";
  private static String RetrieveSelfAPIKeys = "authentication:retrieve_self_api_keys";
  private static String RevokeAnyAPIKey = "authentication:revoke_any_api_key";
  private static String RevokeSelfAPIKey = "authentication:revoke_self_api_key";

  private static SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
  private static SecureRandom secureRandom = new SecureRandom();

  private static Boolean checkSecret(String secret, String encodedSecret) {
    return encoder.matches(secret, encodedSecret);
  }

  private static String hashSecret(String secret) {
    return encoder.encode(secret);
  }

  @Autowired private APIKeyRepository repository;
  @Autowired private AuthenticationService authenticationService;

  public APIKey authenticatedAPIKey(@Valid UUID id, String secret)
      throws EntityNotFound, InsufficientPermission {
    logger.debug("authenticatedAPIKey");
    List<String> subjectScopes = authenticationService.getScopes();

    if (!subjectScopes.contains(AuthenticateAnyAPIKey)) {
      throw new InsufficientPermission();
    }

    APIKey apiKey = repository.findByIdAndRevokedIsFalse(id).orElseThrow(EntityNotFound.supplier());

    if (checkSecret(secret, apiKey.getHashedSecret())) {
      return retrieveApiKey(apiKey.getId());
    }

    throw new EntityNotFound();
  }

  public APIKeyDetails requestAPIKey(String name) throws InsufficientPermission {
    logger.debug("requestAPIKey");
    List<String> subjectScopes = authenticationService.getScopes();

    if (subjectScopes.contains(RequestSelfAPIKey)) {
      UUID subject = UUID.fromString(authenticationService.getSubject());
      byte[] secretBytes = new byte[30];
      secureRandom.nextBytes(secretBytes);
      String secret = Base64.getEncoder().encodeToString(secretBytes);
      APIKey apiKey = new APIKey(subject, name, secret.substring(0, 8), hashSecret(secret));
      apiKey = repository.saveAndFlush(apiKey);

      APIKeyDetails details = new APIKeyDetails();
      details.apiKey = apiKey;
      details.secret = secret;
      return details;
    }

    throw new InsufficientPermission();
  }

  public APIKey retrieveApiKey(@Valid UUID id) throws EntityNotFound, InsufficientPermission {
    logger.debug("retrieveApiKey");
    List<String> subjectScopes = authenticationService.getScopes();

    if (subjectScopes.contains(RetrieveAnyAPIKey)) {
      return repository.findByIdAndRevokedIsFalse(id).orElseThrow(EntityNotFound.supplier());
    }

    if (subjectScopes.contains(RetrieveSelfAPIKey)) {
      String subject = authenticationService.getSubject();
      return repository
          .findBySubjectAndIdAndRevokedIsFalse(subject, id)
          .orElseThrow(EntityNotFound.supplier());
    }

    throw new InsufficientPermission();
  }

  public Page<APIKey> retrieveApiKeys(Pageable pageable) throws InsufficientPermission {
    logger.debug("retrieveApiKeys");
    List<String> subjectScopes = authenticationService.getScopes();

    if (subjectScopes.contains(RetrieveAnyAPIKeys)) {
      return repository.findAllByRevokedIsFalse(pageable);
    }

    if (subjectScopes.contains(RetrieveSelfAPIKeys)) {
      String subject = authenticationService.getSubject();
      return repository.findAllBySubjectAndRevokedIsFalse(subject, pageable);
    }

    throw new InsufficientPermission();
  }

  public void revokeApiKey(UUID id) throws EntityNotFound, InsufficientPermission {
    logger.debug("revokeApiKey");
    String subject = authenticationService.getSubject();
    List<String> subjectScopes = authenticationService.getScopes();

    APIKey apiKey = retrieveApiKey(id);

    if (!subjectScopes.contains(RevokeAnyAPIKey)
        && (!apiKey.getSubject().toString().equals(subject)
            || !subjectScopes.contains(RevokeSelfAPIKey))) {
      throw new InsufficientPermission();
    }

    apiKey.revoke();
    repository.saveAndFlush(apiKey);
  }
}
