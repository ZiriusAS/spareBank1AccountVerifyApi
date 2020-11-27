/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zirius.zerp.spareBank1Api.service;

import javax.annotation.Resource;
import org.junit.jupiter.api.Test;

/**
 *
 * @author karthi
 */


public class BaseServiceTest {

@Test
public void testIsAuthorizedSpareUser() {
    BaseService baseService = new BaseService();
    String accountNo = "";
    String publicId = ""; // SSN
    baseService.isAuthorizedSpareUser(accountNo, publicId);
}
    
}
