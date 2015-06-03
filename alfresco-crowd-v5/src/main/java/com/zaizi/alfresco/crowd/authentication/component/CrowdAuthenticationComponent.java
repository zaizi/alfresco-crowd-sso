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

package com.zaizi.alfresco.crowd.authentication.component;

import net.sf.acegisecurity.Authentication;

import org.alfresco.repo.security.authentication.AbstractAuthenticationComponent;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;

import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.service.client.ClientProperties;
import com.zaizi.alfresco.crowd.authentication.manager.CrowdAuthenticationManager;

/**
 * <p>
 * CrowdAuthenticationComponent class
 * </p>
 * <p>
 * AuthenticationComponent which use Crowd as identity provider to authenticate the users
 * </p>
 * 
 * @author Antonio David Perez Morales <aperez@zaizi.com>
 * 
 */
public class CrowdAuthenticationComponent extends AbstractAuthenticationComponent implements InitializingBean {
    /**
     * Logger
     */
    private final Log logger = LogFactory.getLog(getClass());

    /**
     * CrowdAuthenticationManager
     */
    private final CrowdAuthenticationManager crowdAuthenticationManager;

    /**
     * ClientProperties used to obtain needed crowd properties like application name, application password,
     * etc
     */
    private final ClientProperties clientProperties;

   /**
     * Flag indicating if this authentication component allows guest login
     */
    private boolean allowGuestLogin = true;

    /**
     * X-Forwarded-For for identify client
     */
    private String xffAddr;
    
    /**
     * <p>
     * Creates an instance using the given Crowd manager and client properties
     * </p>
     * 
     * @param crowdAuthenticationManager
     *            The {@code CrowdAuthenticationManager} instance
     * @param clientProperties
     *            The {@code ClientProperties} instance
     */
    public CrowdAuthenticationComponent(CrowdAuthenticationManager crowdAuthenticationManager,
                                        ClientProperties clientProperties) {
        this.crowdAuthenticationManager = crowdAuthenticationManager;
        this.clientProperties = clientProperties;
    }

    /**
     * <p>
     * Performs the authentication using Crowd
     * </p>
     * 
     * @param userName
     *            The user name
     * @param password
     *            The user password
     */
    protected void authenticateImpl(String userName, char[] password) {
        UserAuthenticationContext userAuthnContext = this.createUserAuthenticationContext(userName, password);

        performCrowdAuthentication(userAuthnContext);
    }

    /**
     * <p>
     * Try to obtain a Crowd token using the user and application credentials contained in the user
     * authentication context object
     * </p>
     * 
     * @param userContext
     *            The {@code UserAuthenticationContext} object
     * @return a boolean indicating if the authentication is successful or not
     * 
     * @throws AuthenticationException
     *             if the token from Crowd can be obtained
     */
    private boolean performCrowdAuthentication(UserAuthenticationContext userContext) {
        try {
            /* Get the user token */
            String authToken = this.crowdAuthenticationManager.authenticateUserSSO(userContext);
            if (authToken == null) throw new AuthenticationException("No authToken issued from crowd");
        } catch (Exception e) {
            throw new AuthenticationException(e.getMessage(), e);
        }

        /* Token obtained. Set the current authentication for this user */
        Authentication result = setCurrentUser(userContext.getName());

        return result.isAuthenticated();
    }

    /**
     * <p>
     * Checks if this authentication component allows guest login
     * </p>
     */
    protected boolean implementationAllowsGuestLogin() {
        return this.allowGuestLogin;
    }

    /**
     * <p>
     * Creates the UserAuthenticationComponent object with the user credentials
     * </p>
     * 
     * @param userName
     *            The username
     * @param password
     *            The user password
     * @return The {@code UserAuthenticationCompoent} instance
     */
    private UserAuthenticationContext createUserAuthenticationContext(String userName, char[] password) {
        PasswordCredential passwordCredential = new PasswordCredential(new String(password), false);
        UserAuthenticationContext userAuthenticationContext = new UserAuthenticationContext();
        userAuthenticationContext.setName(userName);
        userAuthenticationContext.setCredential(passwordCredential);
        userAuthenticationContext.setApplication(clientProperties.getApplicationName());
        ValidationFactor[] factors = new ValidationFactor[] {
        		new ValidationFactor("remote_address", "127.0.0.1"),
        		new ValidationFactor("X-Forwarded-For", xffAddr)
        };
        logger.debug("createUserAuthenticationContext factors : " + factors);
        userAuthenticationContext.setValidationFactors(factors);
        logger.debug("createUserAuthenticationContext getValidationFactors : " + userAuthenticationContext.getValidationFactors().toString());
        return userAuthenticationContext;
    }

    /**
     * <p>
     * Sets the allowGuestLogin flag
     * </p>
     * 
     * @param allowGuestLogin
     */
    public void setAllowGuestLogin(boolean allowGuestLogin) {
        this.allowGuestLogin = allowGuestLogin;
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

	@Override
	public void afterPropertiesSet() throws Exception {
		// Do nothing
		logger.debug("afterPropertiesSet called. ");
	}

}
