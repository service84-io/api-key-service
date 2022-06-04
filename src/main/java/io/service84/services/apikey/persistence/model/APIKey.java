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

package io.service84.services.apikey.persistence.model;

import java.time.LocalDateTime;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.Id;

import org.hibernate.envers.Audited;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Audited
@EntityListeners(AuditingEntityListener.class)
public class APIKey {
  @Id private UUID id = UUID.randomUUID();

  @CreatedDate private LocalDateTime createdDate;
  @CreatedBy private String createdBy;
  @LastModifiedDate private LocalDateTime modifiedDate;
  @LastModifiedBy private String modifiedBy;

  @Column(updatable = false, nullable = false)
  private UUID subject;

  @Column(nullable = false)
  private String name;

  @Column(nullable = false)
  private Boolean revoked;

  @Column(updatable = false, nullable = false)
  private String secretPrefix;

  @Column(updatable = false, nullable = false, columnDefinition = "VARCHAR(65535)")
  private String hashedSecret;

  protected APIKey() {}

  public APIKey(UUID subject, String name, String secretPrefix, String hashedSecret) {
    this.subject = subject;
    this.name = name;
    this.revoked = Boolean.FALSE;
    this.secretPrefix = secretPrefix;
    this.hashedSecret = hashedSecret;
  }

  public String getHashedSecret() {
    return hashedSecret;
  }

  public UUID getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public String getSecretPrefix() {
    return secretPrefix;
  }

  public UUID getSubject() {
    return subject;
  }

  public void revoke() {
    this.revoked = Boolean.TRUE;
  }
}
