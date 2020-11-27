/*
 * CRS account authorisation API
 * This service exposes an API to validate approver’s right of disposal to account. This API accesses the same authorization data as is used when TietoEvry validates approver data.
 *
 * OpenAPI spec version: v1
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */

package com.evry.model;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.v3.oas.annotations.media.Schema;
import java.io.IOException;
/**
 * Represents a person-customer(user) with a SSN/publicID and a status
 */
@Schema(description = "Represents a person-customer(user) with a SSN/publicID and a status")
@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2020-11-20T05:28:54.388Z[GMT]")
public class AuthorisationStatus {
  @SerializedName("publicID")
  private String publicID = null;

  /**
   * The authorisation status of the user defined by publicID to the account
   */
  @JsonAdapter(StatusEnum.Adapter.class)
  public enum StatusEnum {
    OK("OK"),
    REJECTED("REJECTED");

    private String value;

    StatusEnum(String value) {
      this.value = value;
    }
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }
    public static StatusEnum fromValue(String text) {
      for (StatusEnum b : StatusEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
    public static class Adapter extends TypeAdapter<StatusEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final StatusEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public StatusEnum read(final JsonReader jsonReader) throws IOException {
        String value = jsonReader.nextString();
        return StatusEnum.fromValue(String.valueOf(value));
      }
    }
  }  @SerializedName("status")
  private StatusEnum status = null;

  public AuthorisationStatus publicID(String publicID) {
    this.publicID = publicID;
    return this;
  }

   /**
   * Refers to the publicID/SSN in CustomerPublic used in request
   * @return publicID
  **/
  @Schema(description = "Refers to the publicID/SSN in CustomerPublic used in request")
  public String getPublicID() {
    return publicID;
  }

  public void setPublicID(String publicID) {
    this.publicID = publicID;
  }

  public AuthorisationStatus status(StatusEnum status) {
    this.status = status;
    return this;
  }

   /**
   * The authorisation status of the user defined by publicID to the account
   * @return status
  **/
  @Schema(description = "The authorisation status of the user defined by publicID to the account")
  public StatusEnum getStatus() {
    return status;
  }

  public void setStatus(StatusEnum status) {
    this.status = status;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuthorisationStatus authorisationStatus = (AuthorisationStatus) o;
    return Objects.equals(this.publicID, authorisationStatus.publicID) &&
        Objects.equals(this.status, authorisationStatus.status);
  }

  @Override
  public int hashCode() {
    return Objects.hash(publicID, status);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuthorisationStatus {\n");
    
    sb.append("    publicID: ").append(toIndentedString(publicID)).append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}
