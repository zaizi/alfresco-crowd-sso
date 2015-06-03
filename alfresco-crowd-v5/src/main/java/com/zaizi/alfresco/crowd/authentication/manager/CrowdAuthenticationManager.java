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

package com.zaizi.alfresco.crowd.authentication.manager;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;

import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.service.client.CrowdClient;

/**
 * <p>CrowdAuthenticationManager class</p>
 * <p>This class manages the authentication of users through Atlassian Crowd</p>
 * 
 * @author Antonio David Perez Morales <aperez@zaizi.com>
 *
 */
public class CrowdAuthenticationManager implements InitializingBean {

    private final Log logger = LogFactory.getLog(getClass());
    
    /**
     * The REST Crowd Client
     */
    private CrowdClient crowdClient;

    /**
     * <p>Creates an instance using the given Crowd Client</p>
     * 
     * @param crowdClient The {@code CrowdClient} to use
     */
    public CrowdAuthenticationManager(CrowdClient crowdClient) {
        this.crowdClient = crowdClient;
    }

    /**
     * <p>
     * Authenticates an user using Crowd
     * </p>
     * 
     * @param userAuthContext
     *            the authentication context for the user containing the username and the user credentials
     * @return boolean indicating whether the user has been authenticated successfully or not
     */
    public boolean authenticate(UserAuthenticationContext userAuthContext) {
        /* TODO */
        return false;
    }

    /**
     * <p>
     * Authenticate an user using SSO
     * </p>
     * <p>
     * This method will return a token for this user to be used in SSO environment
     * </p>
     * 
     * @param userAuthenticationContext
     *            the authentication context for the user containing the username and the user credentials
     * @return the token for this user to be used for Single Sign On or null if the authentication fails or an
     *         error ocurred
     */
    public String authenticateUserSSO(UserAuthenticationContext userAuthenticationContext) {
        try {
            String crowdToken = this.crowdClient.authenticateSSOUser(userAuthenticationContext);
            return crowdToken;
        } catch (Exception e) {
            logger.debug("Error authenticating user through Crowd: "+e.getMessage());
            e.printStackTrace();
        }
        
        return null;
    }

    /**
     * <p>Checks if the user identified by the token is authenticated or not</p>
     * @param token the token to be checked
     * @param validationFactors the validation factors to be used in the checking
     * @return a {@code boolean} indicating whether the user is authenticated or not
     */
    public boolean isAuthenticated(String token, List<ValidationFactor> validationFactors) {
        try {
            this.crowdClient.validateSSOAuthentication(token, validationFactors);
            return true;
        } catch (Exception e) {
            logger.debug("Token not valid");
        }
        
        return false;
    }
    
    @Override
    public void afterPropertiesSet() throws Exception {
        //Checkings after properties are set
    }

}
