/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zirius.zerp.spareBank1Api.service;

import com.evry.client.ApiClient;
import com.evry.client.ApiException;
import com.evry.client.JSON;
import com.evry.client.api.AuthorizationsApi;
import com.evry.model.AccountAccess;
import com.evry.model.AccountAccessResult;
import com.evry.model.AuthorisationRequest;
import com.evry.model.AuthorisationResponse;
import com.evry.model.AuthorisationStatus;
import com.evry.model.CustomerPublic;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.auth.signatures.PEM;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;
import org.tomitribe.auth.signatures.Verifier;

/**
 *
 * @author karthi
 */
@Service
public class BaseService {
    
    private final String privateKeyPath = ""; //Path Private key to be used to sign the http header
    private final String publicKeyPath = "";  //Path Public key to be used to verify the signed http header

    // private static String apiURL = "https://bf-esb-internet.fscustomertest.evry.com/secesb/rest/crs-cts-a1"; // Test URL
    private String apiURL = "https://bf-esb-internet.edb.com/secesb/rest/crs"; //Live URL

    private String clientName = ""; //Client name to be received from bank

    private String dataowner = ""; //"Dataowner id to be received from bank eg.1801";

    private String origin = ""; //"origin to be received from bank eg.ERP-(erp vendor name)";

    private String customerId = ""; //Organization id of the customer

    private String userId = ""; //User SSN who initiated the verification request

    private String keyId = ""; //Key id of the key used to verify the signature- can be received from bank

    private String sign = "";
    
    final String method = "POST";
    
    public static void main(String[] args) throws ApiException {
        BaseService bs = new BaseService();
        String accountNo = ""; //Bank account number
        String publicId = ""; // SSN of the persion to be verified with Bank account number
        bs.isAuthorizedSpareUser(accountNo, publicId);
    }
    
    private AuthorisationRequest getAuthorisationRequest(String accountNumber, String publicID) {
        AuthorisationRequest authRequest = new AuthorisationRequest();
        
        AccountAccess accountAccess = new AccountAccess();
        accountAccess.setAccountNumber(accountNumber);
        accountAccess.setPaymentType(AccountAccess.PaymentTypeEnum.PAYMENT);
        List<AccountAccess> accountAccessList = new ArrayList<>();
        accountAccessList.add(accountAccess);
        CustomerPublic cp = new CustomerPublic();
        cp.setPublicID(publicID);
        cp.setIsoCountryCode("NO");
        cp.setAmlStatus(CustomerPublic.AmlStatusEnum.OK);
        
        authRequest.setAccountList(accountAccessList);
        authRequest.setCustomerPublic1(cp);
        
        return authRequest;
    }
    
    Boolean isAuthorizedSpareUser(String accountNumber, String publicID) {
        Boolean isAuthorized = Boolean.FALSE;
        try {
            AuthorizationsApi authApi = new AuthorizationsApi();
            ApiClient apiClient = authApi.getApiClient();
            apiClient.setDebugging(true);
            JSON json = new JSON();
            apiClient.setBasePath(apiURL);
            UUID uuid = UUID.randomUUID();
            String reqid = uuid.toString();
            BaseService bs = new BaseService();
            AuthorisationRequest authReq = bs.getAuthorisationRequest(accountNumber, publicID);
            String strBody = json.serialize(authReq);
            
            String digest = bs.generateDigest(strBody);
            
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("X-EVRY-CLIENT-CLIENTNAME", clientName);
            headers.put("X-EVRY-DATAOWNERORGID", dataowner);
            headers.put("X-EVRY-CLIENT-REQUESTID", reqid);
            headers.put("X-EVRY-CUSTOMERID", customerId);
            headers.put("X-EVRY-USERID", userId);
            headers.put("digest", digest);
            
            String signature = generateSignature(headers, "/secesb/rest/crs/v1/authorize");
            
            try {
                if (verifyGeneratedSignature(headers, "/secesb/rest/crs/v1/authorize", reqid)) {
                    System.out.println("Signature verification success");
                } else {
                    System.out.println("Signature verification failed");
                    return false;
                }
                AuthorisationResponse authResponse = authApi.authorize(authReq, reqid, clientName, dataowner, origin, customerId, userId, signature, digest);
                if (authResponse != null && authResponse.getAccountAccessResultList() != null) {
                    for (AccountAccessResult accountAccessResult : authResponse.getAccountAccessResultList()) {
                        if (accountAccessResult != null && accountAccessResult.getAuthorisationStatus1() != null) {
                            if (accountAccessResult.getAuthorisationStatus1().getPublicID().equals(publicID) 
                                    && accountAccessResult.getAccountNumber().equals(accountNumber)
                                    && accountAccessResult.getAuthorisationStatus1().getStatus().equals(AuthorisationStatus.StatusEnum.OK)) {
                             isAuthorized = true;   
                                System.out.println("The publicID : "+ publicID +" is authorised with account number : "+ accountNumber);
                            }
                        }
                    }
                }
                System.out.println("authResponse" + authResponse.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
            
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return isAuthorized;
    }
    
    public String generateDigest(String bodyText) throws NoSuchAlgorithmException {
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bodyText.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();
        return "SHA-256=" + Base64.getEncoder().encodeToString(digest);
    }
    
    public String generateSignature(Map<String, String> headers, String uri) throws Exception {
        
        File privateKeyFile = new File(privateKeyPath);
        byte[] keyBytes = null;
        
        try (InputStream is = new FileInputStream(privateKeyFile); DataInputStream dis = new DataInputStream(is)) {
            
            keyBytes = new byte[(int) privateKeyFile.length()];
            dis.readFully(keyBytes);
            
        }
        
        List<String> paramsList = new ArrayList<String>(headers.keySet());
        
        paramsList.add("(request-target)");
        paramsList.add("(Created)");
        
        final Signature signature = new Signature(keyId, "rsa-sha256", "rsa-sha256", null, null, paramsList);
        
        final PrivateKey key = PEM.readPrivateKey(new ByteArrayInputStream(keyBytes));
        
        final Signer signer = new Signer(key, signature);
        
        final Signature signed = signer.sign(method, uri, headers);
        sign = signed.toString().replace("Signature", "");
        
        return sign;
    }
    
    public Boolean verifyGeneratedSignature(Map<String, String> headers, String uri, String requestid) throws Exception {
        
        File publicKeyFile = new File(publicKeyPath);
        byte[] keyBytes = null;
        try (InputStream is = new FileInputStream(publicKeyFile); DataInputStream dis = new DataInputStream(is)) {
            
            keyBytes = new byte[(int) publicKeyFile.length()];
            dis.readFully(keyBytes);
        }
        
        final Signature signature = Signature.fromString(sign, Algorithm.RSA_SHA256);
        
        final PublicKey key = PEM.readPublicKey(new ByteArrayInputStream(keyBytes));
        final Verifier verifier = new Verifier(key, signature);
        
        final Boolean verifies = verifier.verify(method, uri, headers);
        
        return verifies;
        
    }
    
}
