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

package io.service84.services.apikey.persistence.repository;

import java.util.Optional;
import java.util.UUID;

import javax.validation.Valid;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import io.service84.services.apikey.persistence.model.APIKey;

@Repository("DFF29C27-337E-4795-B761-31BC8D5B8299")
public interface APIKeyRepository
    extends JpaRepository<APIKey, UUID>, JpaSpecificationExecutor<APIKey> {
  Page<APIKey> findAllByRevokedIsFalse(Pageable pageable);

  Page<APIKey> findAllBySubjectAndRevokedIsFalse(String subject, Pageable pageable);

  Optional<APIKey> findByIdAndRevokedIsFalse(@Valid UUID id);

  Optional<APIKey> findBySubjectAndIdAndRevokedIsFalse(String subject, @Valid UUID id);
}
