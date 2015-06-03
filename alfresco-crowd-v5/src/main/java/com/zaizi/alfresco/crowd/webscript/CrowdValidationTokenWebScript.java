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

import org.alfresco.repo.security.authentication.AuthenticationComponent;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.CrowdClient;

/**
 * <p>CrowdValidationTokenWebScript class</p>
 * <p>This WebScript is responsible of validate a Crowd token and return an Alfresco ticket for the user behind the token</p>
 * 
 * @author Antonio David Perez Morales <aperez@zaizi.com>
 *
 */
public class CrowdValidationTokenWebScript extends DeclarativeWebScript{

    /* Constants */
    private static final String TOKEN_PARAMETER = "token";
    private static final String MODEL_VALID_KEY = "valid";
    private static final String MODEL_ALF_TOKEN_KEY = "alf_token";
    private static final String MODEL_USER_KEY = "user";
    
    private static Log logger = LogFactory.getLog(CrowdValidationTokenWebScript.class);
        
    private AuthenticationService authenticationService;
    private AuthenticationComponent authenticationComponent;
    private CrowdClient crowdClient;
    
    /**
     * <p>Perform the crowd token validation</p>
     * 
     * @param req the {@code WebScriptRequest} request
     * @param status the {@code Status}
     * @param Cache the {@code Cache}
     * 
     * @return a map containing the properties to be passed to the model
     */
    @Override
    protected Map<String,Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        
        Map<String, Object> model = new HashMap<String, Object>();
        String token = req.getParameter(TOKEN_PARAMETER);
        logger.debug("Validating crowd token");
        try {
            /* Validate the token */
            User crowdUser = crowdClient.findUserFromSSOToken(token);
            String userName = crowdUser.getName();
            logger.debug("Token valid. User is "+userName);
            
            /* Set current username and then obtain the current ticket for this user */
            this.authenticationComponent.setCurrentUser(userName);
            String alfToken = this.authenticationService.getCurrentTicket();
            
            /* Model properties to be passed to the webscript template */
            model.put(MODEL_VALID_KEY, Boolean.toString(true));
            model.put(MODEL_ALF_TOKEN_KEY, alfToken);
            model.put(MODEL_USER_KEY, crowdUser.getName());
        }
        catch(Exception exception) {
            /* Token not valid */
            logger.debug("Error validating token: "+exception.getMessage());
            model.put(MODEL_VALID_KEY, Boolean.toString(false));
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
     * <p>Sets the authentication component</p>
     * @param authenticationComponent the {@code AuthenticationComponent} to be used
     */
    public void setAuthenticationComponent(AuthenticationComponent authenticationComponent) {
        this.authenticationComponent = authenticationComponent;
    }
    
    /**
     * <p>Sets the Crowd client</p>
     * @param crowdClient the {@code CrowdClient} to be used to communicate with Crowd
     */
    public void setCrowdClient(CrowdClient crowdClient) {
        this.crowdClient = crowdClient;
    }
    
}
