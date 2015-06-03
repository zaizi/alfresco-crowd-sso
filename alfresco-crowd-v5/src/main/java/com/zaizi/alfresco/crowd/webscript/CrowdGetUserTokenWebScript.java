/**
 * Copyright 2015 Zaizi Limited.
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.zaizi.alfresco.crowd.webscript;

import java.util.HashMap;
import java.util.Map;

import org.alfresco.service.cmr.security.AuthenticationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.CrowdClient;

/**
 * <p>
 * CrowdGetUserToken class
 * </p>
 * <p>
 * This WebScript is responsible of obtain the Crowd token for a given user
 * </p>
 * 
 * @author Antonio David Perez Morales <aperez@zaizi.com>
 * 
 */
public class CrowdGetUserTokenWebScript extends DeclarativeWebScript {
    
    /* Constants */
    private static final String TOKEN_KEY = "token";
    
    private static Log logger = LogFactory.getLog(CrowdGetUserTokenWebScript.class);
    
    private AuthenticationService authenticationService;
    private CrowdClient crowdClient;
    private ClientProperties clientProperties;
    /**
     * X-Forwarded-For for identify client
     */
    private String xffAddr;
    
    
    /**
     * <p>Try to obtain a Crowd token for the current authenticated user</p>
     * 
     * @param req the {@code WebScriptRequest} request
     * @param status the {@code Status}
     * @param Cache the {@code Cache}
     * 
     * @return a map containing the properties to be passed to the model
     */
    @Override
    protected Map<String,Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
    	String userName = authenticationService.getCurrentUserName();
        
        Map<String,Object> model = new HashMap<String,Object>();
        
        UserAuthenticationContext userAuthenticationContext = new UserAuthenticationContext();
        userAuthenticationContext.setName(userName);
        userAuthenticationContext.setCredential(new PasswordCredential("", false));
        ValidationFactor[] factors = new ValidationFactor[] {
        		new ValidationFactor("remote_address", "127.0.0.1"),
        		new ValidationFactor("X-Forwarded-For", xffAddr)
        };
        logger.debug("executeImpl factors : " + factors);
        userAuthenticationContext.setValidationFactors(factors);
        //userAuthenticationContext.setValidationFactors(new ValidationFactor[0]);
        userAuthenticationContext.setApplication(clientProperties.getApplicationName());
        logger.debug("Trying to obtain token for user "+userName);
        try {
            String token = this.crowdClient.authenticateSSOUserWithoutValidatingPassword(userAuthenticationContext);
            logger.debug("Token obtained");
            model.put(TOKEN_KEY, token);
        } catch (Exception e) {
            logger.debug("Could not obtain a token");
        }
        
        return model;
    }
    
    /**
     * <p>Sets the authentication service</p>
     * @param authenticationService the {@code AuthenticationService} to be used
     */
    public void setAuthenticationService(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }
    
    /**
     * <p>Sets the Crowd client</p>
     * @param crowdClient the {@code CrowdClient} to be used to communicate with Crowd
     */
    public void setCrowdClient(CrowdClient crowdClient) {
        this.crowdClient = crowdClient;
    }
    
    /**
     * <p>Sets the Client Properties</p>
     * @param client properties the {@code ClientProperties} to be used to
     */
    public void setClientProperties(ClientProperties clientProperties) {
        this.clientProperties = clientProperties;
    }

    /**
     * <p>
     * Sets the 'X-Forwarded-For' Address
     * </p>
     * 
     * @param xffAddr
     */
    public void setXffAddr(String xffAddr) {
        this.xffAddr = xffAddr;
    }
}
