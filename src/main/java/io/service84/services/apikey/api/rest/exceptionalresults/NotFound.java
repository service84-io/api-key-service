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

package io.service84.services.apikey.api.rest.exceptionalresults;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;

import io.service84.library.exceptionalresult.models.ExceptionalException;
import io.service84.services.apikey.dto.ErrorDTO;

public class NotFound extends ExceptionalException {
  private static final long serialVersionUID = 1L;
  private static final HttpStatus status = HttpStatus.NOT_FOUND;

  private static ErrorDTO getError(String message, String path) {
    ErrorDTO error = new ErrorDTO();
    error.setTimestamp(LocalDateTime.now());
    error.setStatus(status.value());
    error.setError(status.getReasonPhrase());
    error.setMessage(message);
    error.setPath(path);
    return error;
  }

  public NotFound() {
    this(status.getReasonPhrase());
  }

  public NotFound(String message) {
    this(message, null);
  }

  public NotFound(String message, String path) {
    super(status, getError(message, path));
  }
}
