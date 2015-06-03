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

package com.zaizi.alfresco.crowd.authentication.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.FrameworkBean;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.webscripts.connector.AlfrescoAuthenticator;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorSession;
import org.springframework.extensions.webscripts.connector.CredentialVault;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.web.context.support.WebApplicationContextUtils;

import com.zaizi.alfresco.crowd.authentication.cookie.CookieManager;
import com.zaizi.alfresco.crowd.authentication.cookie.exception.CookieNotFoundException;

/**
 * 
 * <p>
 * CrowdSSOFilter class
 * </p>
 * <p>
 * Java Filter used to authenticate the user using Atlassian Crowd in Alfresco Share
 * </p>
 * <p>
 * This filter makes use of a WebScript in Alfresco Explorer to check the validity of the Crowd token if
 * exists
 * </p>
 * 
 * @author Antonio David Perez Morales <aperez@zaizi.com>
 * 
 */
public class CrowdSSOFilter implements Filter {
    /* Constants Definitions */

    /**
     * The endpoint used to obtain the connector
     */
    private static final String ENDPOINT_ID = "alfresco";

    /**
     * Valid key to retrieve the token validity in the Crowd Validation Token response
     */
    private static final String VALID_KEY = "valid";

    /**
     * Alfresco Ticket key to retrieve the alfresco token in the Crowd Validation Token response
     */
    private static final String ALF_TICKET_KEY = "ticket";

    /**
     * Crowd Token key to retrieve the Crowd token in the Crowd Get Token response
     */
    private static final String TOKEN_KEY = "token";
    
    /**
     * User key to retrieve the user in the Crowd Validation Token response
     */
    private static final String USER_KEY = "user";

    /**
     * Crowd Token Validation WebScript URL
     */
    private static final String CROWD_TOKEN_VALIDATION_URL = "/crowd/validateToken?token=%1$s";

    /**
     * Crowd Get User Token WebScript URL
     */
    private static final String CROWD_GET_TOKEN = "/crowd/getToken";
    /**
     * Crowd Cookie Name
     */
    private static final String CROWD_COOKIE_NAME = "crowd.token_key";

    /**
     * Logger
     */
    private static final Log logger = LogFactory.getLog(CrowdSSOFilter.class);

    /**
     * Servlet Context
     */
    private ServletContext servletContext;

    /**
     * FrameworkBean used to deal with connectors (connector.service) and connector sessions
     */
    private FrameworkBean frameworkUtils;

    /**
     * <p>
     * Filter initialization
     * </p>
     * 
     * @param filterConfig
     *            The filter configuration
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.servletContext = filterConfig.getServletContext();

        ApplicationContext context = getApplicationContext();

        /*
         * retrieve the framework utils bean used to deal with connectors (connector.service) and connector
         * sessions
         */
        this.frameworkUtils = (FrameworkBean) context.getBean("framework.utils");
    }

    /**
     * <p>
     * Retrieves the root application context
     * </p>
     * 
     * @return The current Spring Application Context
     */
    private ApplicationContext getApplicationContext() {
        return WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
    }

    /**
     * <p>
     * The filter checks if a crowd cookie exists in the request in order to try to authenticate automatically
     * the user
     * </p>
     * 
     * @param request
     *            The request
     * @param response
     *            The response
     * @param chain
     *            The filter chain containing the rest of the configured filters
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
                                                                                             ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String endpoint = this.frameworkUtils.getEndpoint(ENDPOINT_ID).getEndpointUrl();

        /* Create a Remote client for the configured endpoint id */
        RemoteClient remote = createRemoteClient(endpoint, httpRequest.getSession(true));

        /* Manages the cookies */
        CookieManager cookieManager = new CookieManager();

        String cookieValue = null;
        Boolean crowdCookiePresent = false;
        
        try {
            cookieValue = cookieManager.getCookieValue(httpRequest, CROWD_COOKIE_NAME).toString();
            crowdCookiePresent = true;
        } catch (CookieNotFoundException e) {
            logger.debug("Crowd cookie not found in the request");
        }

        /* If authenticated, trying to enable SSO if it is not enabled yet */
        if (AuthenticationUtil.isAuthenticated(httpRequest)) {
            // Checks if Crowd Cookie exists. If not, trying to create a Crowd token to enable SSO
            if (!crowdCookiePresent) {
                enableSSO(remote, cookieManager, httpRequest, httpResponse);
            }

            /* Continue the filter chain */
            chain.doFilter(httpRequest, response);
            return;
        }

        /* If not authenticated and no cookie present, continue the chain */
        if(!crowdCookiePresent) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }
        
        /* Cookie present. Trying to create Share session */
        try {

            /* Call the validation token endpoint */
            Response resp = remote.call(String.format(CROWD_TOKEN_VALIDATION_URL, cookieValue));

            /* JSON Response */
            JSONObject jsonResp = new JSONObject(resp.getResponse());

            /* If it is a valid response... */
            if (jsonResp.getBoolean(VALID_KEY)) {
                // Use the token and user to create the session in the connector and share
                String alfTicket = jsonResp.getString(ALF_TICKET_KEY);
                String userId = jsonResp.getString(USER_KEY);

                /* Set credentials in the connector and login the user in Share */
                setUserCredentialsInConnector(httpRequest.getSession(), alfTicket, userId);
                AuthenticationUtil.login(httpRequest, httpResponse, userId);
            }

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        chain.doFilter(httpRequest, httpResponse);

    }

    /**
     * <p>Enable the SSO, obtaining a Crowd token for the already authenticated user and putting it into a Crowd cookie<p>
     * 
     * @param remote the {@code RemoteClient} object to communicate with Alfresco
     * @param cookieManager the {@code CookieManager} object used to obtain and create cookies
     * @param request the {@code HttpServletRequest} object
     * @param response the {@code HttpServletResponse} object where put the token to
     */
    private void enableSSO(RemoteClient remote, CookieManager cookieManager, HttpServletRequest request, HttpServletResponse response) {
        Response resp = remote.call(CROWD_GET_TOKEN);
        try {
            JSONObject jsonResponse = new JSONObject(resp.getResponse());
            if(jsonResponse.has(TOKEN_KEY))
                cookieManager.putCookieValue(request, response, CROWD_COOKIE_NAME, -1 , jsonResponse.getString(TOKEN_KEY));
        } catch (JSONException e) {
            logger.debug("Unable to process the response");
        }
    }
    
    
    /**
     * <p>
     * Sets the user credentials (username and ticket) in the connector used to make the requests to
     * communicate with Alfresco
     * </p>
     * 
     * @param session
     *            the {@code HttpSession} object containing the user session
     * 
     * @param alfTicket
     *            the {@code String} containing a valid user ticket to be used to access Alfresco services
     * @param userId
     *            the {@code String} containing the username
     * 
     * @throws ConnectorServiceException
     *             if the connector can be retrieved
     */
    private void setUserCredentialsInConnector(HttpSession session, String alfTicket, String userId) throws ConnectorServiceException {
        // Gets the connector for the configured endpoint using FrameworkBean

        Connector connector = this.frameworkUtils.getConnector(session, userId, ENDPOINT_ID);
        // Creating the credentials for the session and username
        CredentialVault vault = this.frameworkUtils.getCredentialVault(session, userId);
        Credentials credentials = vault.newCredentials(ENDPOINT_ID);
        credentials.setProperty(Credentials.CREDENTIAL_USERNAME, userId);
        connector.setCredentials(credentials);

        // Sets the credentials in the connector session
        ConnectorSession cs = connector.getConnectorSession();

        cs.setParameter(AlfrescoAuthenticator.CS_PARAM_ALF_TICKET, alfTicket);
    }

    /**
     * <p>Create a remote client for the given endpoint trying to add the ticket if exists in the client</p> 
     * @param endpoint the endpoint for the remote client
     * @return a {@code RemoteClient} instance
     */
    private RemoteClient createRemoteClient(String endpoint, HttpSession session) {
        RemoteClient remote = new RemoteClient();
        remote.setEndpoint(endpoint);
        ConnectorSession connectorSession = this.frameworkUtils.getConnectorSession(session, ENDPOINT_ID);
        String alf_ticket = connectorSession.getParameter(AlfrescoAuthenticator.CS_PARAM_ALF_TICKET);
        if(alf_ticket != null && !alf_ticket.isEmpty())
            remote.setTicket(alf_ticket);
        return remote;
    }
    
    @Override
    public void destroy() {
        // TODO Auto-generated method stub

    }

}
