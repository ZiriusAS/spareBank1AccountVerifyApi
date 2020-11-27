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
import com.evry.model.AuthorisationStatus;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.v3.oas.annotations.media.Schema;
import java.io.IOException;
/**
 * Represents a account along with relevant information of the account
 */
@Schema(description = "Represents a account along with relevant information of the account")
@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2020-11-20T05:28:54.388Z[GMT]")
public class AccountAccessResult {
  @SerializedName("accountNumber")
  private String accountNumber = null;

  @SerializedName("authorisationStatus1")
  private AuthorisationStatus authorisationStatus1 = null;

  @SerializedName("authorisationStatus2")
  private AuthorisationStatus authorisationStatus2 = null;

  @SerializedName("organisationId")
  private String organisationId = null;

  @SerializedName("customerName")
  private String customerName = null;

  @SerializedName("agreementName")
  private String agreementName = null;

  @SerializedName("agreementIntId")
  private String agreementIntId = null;

  @SerializedName("customerIntId")
  private String customerIntId = null;

  /**
   * The number of reqired approvals for payments on the account.
   */
  @JsonAdapter(NumberOfApproversEnum.Adapter.class)
  public enum NumberOfApproversEnum {
    NUMBER_1(1),
    NUMBER_2(2);

    private Integer value;

    NumberOfApproversEnum(Integer value) {
      this.value = value;
    }
    public Integer getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }
    public static NumberOfApproversEnum fromValue(String text) {
      for (NumberOfApproversEnum b : NumberOfApproversEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
    public static class Adapter extends TypeAdapter<NumberOfApproversEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final NumberOfApproversEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public NumberOfApproversEnum read(final JsonReader jsonReader) throws IOException {
        Integer value = jsonReader.nextInt();
        return NumberOfApproversEnum.fromValue(String.valueOf(value));
      }
    }
  }  @SerializedName("numberOfApprovers")
  private NumberOfApproversEnum numberOfApprovers = null;

  public AccountAccessResult accountNumber(String accountNumber) {
    this.accountNumber = accountNumber;
    return this;
  }

   /**
   * The account number in question
   * @return accountNumber
  **/
  @Schema(required = true, description = "The account number in question")
  public String getAccountNumber() {
    return accountNumber;
  }

  public void setAccountNumber(String accountNumber) {
    this.accountNumber = accountNumber;
  }

  public AccountAccessResult authorisationStatus1(AuthorisationStatus authorisationStatus1) {
    this.authorisationStatus1 = authorisationStatus1;
    return this;
  }

   /**
   * Get authorisationStatus1
   * @return authorisationStatus1
  **/
  @Schema(required = true, description = "")
  public AuthorisationStatus getAuthorisationStatus1() {
    return authorisationStatus1;
  }

  public void setAuthorisationStatus1(AuthorisationStatus authorisationStatus1) {
    this.authorisationStatus1 = authorisationStatus1;
  }

  public AccountAccessResult authorisationStatus2(AuthorisationStatus authorisationStatus2) {
    this.authorisationStatus2 = authorisationStatus2;
    return this;
  }

   /**
   * Get authorisationStatus2
   * @return authorisationStatus2
  **/
  @Schema(description = "")
  public AuthorisationStatus getAuthorisationStatus2() {
    return authorisationStatus2;
  }

  public void setAuthorisationStatus2(AuthorisationStatus authorisationStatus2) {
    this.authorisationStatus2 = authorisationStatus2;
  }

  public AccountAccessResult organisationId(String organisationId) {
    this.organisationId = organisationId;
    return this;
  }

   /**
   * The organisationId (ForetaksNummer) that owns the account
   * @return organisationId
  **/
  @Schema(required = true, description = "The organisationId (ForetaksNummer) that owns the account")
  public String getOrganisationId() {
    return organisationId;
  }

  public void setOrganisationId(String organisationId) {
    this.organisationId = organisationId;
  }

  public AccountAccessResult customerName(String customerName) {
    this.customerName = customerName;
    return this;
  }

   /**
   * The customerName that the account belongs to
   * @return customerName
  **/
  @Schema(description = "The customerName that the account belongs to")
  public String getCustomerName() {
    return customerName;
  }

  public void setCustomerName(String customerName) {
    this.customerName = customerName;
  }

  public AccountAccessResult agreementName(String agreementName) {
    this.agreementName = agreementName;
    return this;
  }

   /**
   * The name of the agreement the associated with the account
   * @return agreementName
  **/
  @Schema(description = "The name of the agreement the associated with the account")
  public String getAgreementName() {
    return agreementName;
  }

  public void setAgreementName(String agreementName) {
    this.agreementName = agreementName;
  }

  public AccountAccessResult agreementIntId(String agreementIntId) {
    this.agreementIntId = agreementIntId;
    return this;
  }

   /**
   * The AgreementId (AvtaleID) is the EVRY internal sequence number for the agreement. Used for revision purposes
   * @return agreementIntId
  **/
  @Schema(required = true, description = "The AgreementId (AvtaleID) is the EVRY internal sequence number for the agreement. Used for revision purposes")
  public String getAgreementIntId() {
    return agreementIntId;
  }

  public void setAgreementIntId(String agreementIntId) {
    this.agreementIntId = agreementIntId;
  }

  public AccountAccessResult customerIntId(String customerIntId) {
    this.customerIntId = customerIntId;
    return this;
  }

   /**
   * The customerId (KundeID) is the EVRY internal sequence number for the customer/organisation. Used for revision purposes
   * @return customerIntId
  **/
  @Schema(required = true, description = "The customerId (KundeID) is the EVRY internal sequence number for the customer/organisation. Used for revision purposes")
  public String getCustomerIntId() {
    return customerIntId;
  }

  public void setCustomerIntId(String customerIntId) {
    this.customerIntId = customerIntId;
  }

  public AccountAccessResult numberOfApprovers(NumberOfApproversEnum numberOfApprovers) {
    this.numberOfApprovers = numberOfApprovers;
    return this;
  }

   /**
   * The number of reqired approvals for payments on the account.
   * @return numberOfApprovers
  **/
  @Schema(description = "The number of reqired approvals for payments on the account.")
  public NumberOfApproversEnum getNumberOfApprovers() {
    return numberOfApprovers;
  }

  public void setNumberOfApprovers(NumberOfApproversEnum numberOfApprovers) {
    this.numberOfApprovers = numberOfApprovers;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AccountAccessResult accountAccessResult = (AccountAccessResult) o;
    return Objects.equals(this.accountNumber, accountAccessResult.accountNumber) &&
        Objects.equals(this.authorisationStatus1, accountAccessResult.authorisationStatus1) &&
        Objects.equals(this.authorisationStatus2, accountAccessResult.authorisationStatus2) &&
        Objects.equals(this.organisationId, accountAccessResult.organisationId) &&
        Objects.equals(this.customerName, accountAccessResult.customerName) &&
        Objects.equals(this.agreementName, accountAccessResult.agreementName) &&
        Objects.equals(this.agreementIntId, accountAccessResult.agreementIntId) &&
        Objects.equals(this.customerIntId, accountAccessResult.customerIntId) &&
        Objects.equals(this.numberOfApprovers, accountAccessResult.numberOfApprovers);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accountNumber, authorisationStatus1, authorisationStatus2, organisationId, customerName, agreementName, agreementIntId, customerIntId, numberOfApprovers);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AccountAccessResult {\n");
    
    sb.append("    accountNumber: ").append(toIndentedString(accountNumber)).append("\n");
    sb.append("    authorisationStatus1: ").append(toIndentedString(authorisationStatus1)).append("\n");
    sb.append("    authorisationStatus2: ").append(toIndentedString(authorisationStatus2)).append("\n");
    sb.append("    organisationId: ").append(toIndentedString(organisationId)).append("\n");
    sb.append("    customerName: ").append(toIndentedString(customerName)).append("\n");
    sb.append("    agreementName: ").append(toIndentedString(agreementName)).append("\n");
    sb.append("    agreementIntId: ").append(toIndentedString(agreementIntId)).append("\n");
    sb.append("    customerIntId: ").append(toIndentedString(customerIntId)).append("\n");
    sb.append("    numberOfApprovers: ").append(toIndentedString(numberOfApprovers)).append("\n");
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
