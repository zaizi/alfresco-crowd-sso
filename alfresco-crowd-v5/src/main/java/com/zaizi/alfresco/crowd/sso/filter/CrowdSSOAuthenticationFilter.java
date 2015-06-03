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

package com.zaizi.alfresco.crowd.sso.filter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.transaction.UserTransaction;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.webdav.auth.BaseSSOAuthenticationFilter;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.web.app.Application;
import org.alfresco.web.app.servlet.AuthenticationHelper;
import org.alfresco.web.bean.repository.Repository;
import org.alfresco.web.bean.repository.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.zaizi.alfresco.crowd.authentication.manager.CrowdAuthenticationManager;

/**
 * <p>
 * CrowdSSOAuthenticationFilter class
 * </p>
 * <p>
 * As part of the Crowd Authentication Subsystem, this security filter tries to authenticate the user using an
 * external Atlassian Crowd Server, which manages the user credentials (and permissions)
 * </p>
 * 
 * @author Antonio David Perez Morales <aperez@zaizi.com>
 * 
 */
public class CrowdSSOAuthenticationFilter extends BaseSSOAuthenticationFilter {
    
    /**
     * User password form parameter
     */
    private static final String LOGIN_FORM_USER_PASSWORD = "loginForm:user-password";

    /**
     * User name form parameter
     */
    private static final String LOGIN_FORM_USER_NAME = "loginForm:user-name";

    private final Log logger = LogFactory.getLog(getClass());

    /*
     * This constant is defined by the BaseAuthenticationFilter but it is defined as private
     */
    private static final String ALF_LOGIN_EXTERNAL_AUTH = "_alfExternalAuth";

    /**
     * Browse page to be redirected when login
     */
    private static final String BROWSE_PAGE = "/faces/jsp/browse/browse.jsp";

    /**
     * CrowdAuthenticationManager
     */
    private CrowdAuthenticationManager crowdAuthenticationManager;

    /**
     * CrowdHttpAuthenticator
     */
    private CrowdHttpAuthenticator crowdHttpAuthenticator;

    /**
     * CrowdTokenHelper
     */
    private CrowdHttpTokenHelper crowdTokenHelper;

    /**
     * The Alfresco User
     */
    private User alfrescoUser;

    /**
     * <p>
     * Security filter initialization
     * </p>
     * <p>
     * Sets the login page where the user will be redirected
     * 
     * @param context
     *            the {@code ServletContext} context
     */
    public void init(ServletContext context) {
        String loginPage = Application.getLoginPage(context);
        setLoginPage(loginPage);
    }

    public void doFilter(ServletContext context,
                         ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain chain) throws IOException, ServletException {
        init(context);

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Check if the request has been marked as no authentication required by a previous filter in the
        // chain
        if (isRequestMarkedAsNoAuthenticationNeeded(servletRequest, servletResponse, chain)) {
            return;
        }

        HttpSession httpSession = request.getSession(true);
        User user = (User) httpSession.getAttribute(AuthenticationHelper.AUTHENTICATION_USER);

        // Already authenticated user
        if (user != null) this.logger.debug("Alfresco user logged in: " + user.getUserName());

        try {
            /* Checks if a crowd token exists in the request and tries to validate it */
            String token = this.crowdHttpAuthenticator.getToken(request);

            if (token != null) {
                this.logger.debug("Crowd token found: " + token);

                List<ValidationFactor> validationFactors = crowdTokenHelper.getValidationFactorExtractor()
                        .getValidationFactors(request);
                boolean authenticated = this.crowdAuthenticationManager.isAuthenticated(token,
                    validationFactors);

                this.logger.debug("Is the token authenticated? " + authenticated);
            } else {
                this.logger.debug("No token found in the current request");
            }

            /* If the user is already authenticated in crowd, then obtain the user from crowd */
            if (this.crowdHttpAuthenticator.isAuthenticated(request, response)) {
                com.atlassian.crowd.model.user.User crowdUser = this.crowdHttpAuthenticator.getUser(request);

                if (this.logger.isDebugEnabled()) {
                    this.logger.debug("Crowd User = " + crowdUser.getName());
                }

                /*
                 * If the user is already logged in, we use the current user. Otherwise we use the user
                 * retrieved from Crowd (creating the user if possible)
                 */
                if (isUserAlreadyLoggedIn(crowdUser, httpSession)) useCurrentLoggedUser();
                else {
                    setAuthenticatedUser(request, httpSession, crowdUser.getName());
                }

                if (this.logger.isDebugEnabled()) {
                    this.logger.debug(crowdUser.getName() + " logged through Crowd successfully");
                }

                /*
                 * If the requested page was login page, redirect the user to the home (browse) page because
                 * the user is already logged in
                 */
                if (request.getRequestURI().endsWith(getLoginPage())) {
                    response.sendRedirect(request.getContextPath() + BROWSE_PAGE);
                    return;
                }
                
            } 
            /* The user is not authenticated yet. Try to authenticate the user using Crowd */
            else {
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug("User is not authenticated in Crowd");
                    this.logger.debug("Do we have login page configured? " + hasLoginPage());
                }

                /* If the user is already in the login page, try to authenticate it using Crowd */
                if ((hasLoginPage()) && (request.getRequestURI().endsWith(getLoginPage()) == true)) {
                    if (getLogger().isDebugEnabled()) {
                        getLogger().debug("Login page requested, chaining ...");
                    }

                    /* Performing the Crowd Authentication */
                    this.performCrowdAuthentication(request, response);

                    /* Execute the rest of filters */
                    chain.doFilter(request, response);

                    return;
                }
                
                /* The user is not authenticated and the requested page is not the login page. Redirecting to login page */
                redirectToLoginPage(request, response);
                return;
            }

        } catch (Exception e) {
            this.logger.warn(e.getMessage(), e);
        }

        /* Continue the chain if an error ocurred in Crowd authentication */
        chain.doFilter(request, response);
    }

    /**
     * <p>Try to authenticate the user with Crowd if the username and password are contained in the request</p>
     * 
     * @param request The request
     * @param response The response
     */
    private void performCrowdAuthentication(HttpServletRequest request, HttpServletResponse response) {
        @SuppressWarnings("rawtypes")
        Map parameters = request.getParameterMap();
        if ((parameters.containsKey(LOGIN_FORM_USER_NAME))
            && (parameters.containsKey(LOGIN_FORM_USER_PASSWORD))) {
            String userName = request.getParameter(LOGIN_FORM_USER_NAME);
            String password = request.getParameter(LOGIN_FORM_USER_PASSWORD);
            try {
                this.crowdHttpAuthenticator.authenticate(request, response, userName, password);
            } catch (Exception e) {
                this.logger.warn("Attempted to authenticate with crowd to get a crowd token: "
                                 + e.getMessage());
            }
        }
    }

    /**
     * <p>Destroy does nothing</p>
     */
    public void destroy() {}

    /**
     * <p>Checks if the request has been marked as no authentication needed by a previous filter</p>
     * @param servletRequest The request
     * @param servletResponse The response
     * @param chain The filter chain
     * @return a boolean indicating if the request needs authentication or not
     * 
     * @throws IOException
     * @throws ServletException
     */
    private boolean isRequestMarkedAsNoAuthenticationNeeded(ServletRequest servletRequest,
                                                            ServletResponse servletResponse,
                                                            FilterChain chain) throws IOException,
                                                                              ServletException {
        if (servletRequest.getAttribute(NO_AUTH_REQUIRED) != null) {
            if (this.logger.isDebugEnabled()) {
                this.logger.debug("Authentication not required (filter), chaining ...");
            }

            chain.doFilter(servletRequest, servletResponse);
            return true;
        }
        return false;
    }

    /**
     * <p>Uses the alfresco user as current user</p> 
     */
    private void useCurrentLoggedUser() {
        this.authenticationComponent.setCurrentUser(this.alfrescoUser.getUserName());
    }

    /**
     * <p>Checks if the obtained crowd user is already authenticated in Alfresco</p> 
     * @param crowdUser The crowd user
     * @param httpSession The {@code HttpSession} session
     * @return a {@code} boolean indicating if the user is already logged in or not
     */
    private boolean isUserAlreadyLoggedIn(com.atlassian.crowd.model.user.User crowdUser,
                                          HttpSession httpSession) {
        this.alfrescoUser = ((User) httpSession.getAttribute(AuthenticationHelper.AUTHENTICATION_USER));

        return (this.alfrescoUser != null) && (this.alfrescoUser.getUserName().equals(crowdUser.getName()));
    }

    /**
     * <p>Sets the username passed as parameter as current user, trying to create the user and home if possible, using person service</p>
     * @param request The {@code HttpServletRequest} request
     * @param httpSession the {@code HttpSession} session
     * @param userName The username
     */
    private void setAuthenticatedUser(HttpServletRequest request, HttpSession httpSession, String userName) {
        this.authenticationComponent.setCurrentUser(userName);

        UserTransaction tx = this.transactionService.getUserTransaction();
        NodeRef homeSpaceRef = null;
        User user;
        try {
            tx.begin();
            user = new User(userName, this.authenticationService.getCurrentTicket(),
                    this.personService.getPerson(userName));
            homeSpaceRef = (NodeRef) this.nodeService.getProperty(this.personService.getPerson(userName),
                ContentModel.PROP_HOMEFOLDER);
            if (homeSpaceRef == null) {
                this.logger.warn("Home Folder is null for user '" + userName + "', using company_home.");
                homeSpaceRef = this.nodeService.getRootNode(Repository.getStoreRef());
            }
            user.setHomeSpaceId(homeSpaceRef.getId());
            tx.commit();
        } catch (Throwable ex) {
            this.logger.error(ex);
            try {
                tx.rollback();
            } catch (Exception ex2) {
                this.logger.error("Failed to rollback transaction", ex2);
            }

            if ((ex instanceof RuntimeException)) {
                throw ((RuntimeException) ex);
            }
            throw new RuntimeException("Failed to set authenticated user", ex);
        }

        /* Setting the user as current user in the session */
        httpSession.setAttribute(AuthenticationHelper.AUTHENTICATION_USER, user);
        /* Sets Login external auth */
        httpSession.setAttribute(ALF_LOGIN_EXTERNAL_AUTH, true);
    }

    /**
     * <p>Gets the logger</p>
     * @return the logger
     */
    protected Log getLogger() {
        return this.logger;
    }

    /**
     * <p>Sets the Crowd Authentication Manager to use</p>
     * @param crowdAuthenticationManager The {@code CrowdAuthenticationManager} object
     */
    public void setCrowdAuthenticationManager(CrowdAuthenticationManager crowdAuthenticationManager) {
        this.crowdAuthenticationManager = crowdAuthenticationManager;
    }

    /**
     * <p>Sets the Crowd Http Authenticator to use</p>
     * @param crowdHttpAuthenticator the {@code CrowdHttpAuthenticator} object
     */
    public void setCrowdHttpAuthenticator(CrowdHttpAuthenticator crowdHttpAuthenticator) {
        this.crowdHttpAuthenticator = crowdHttpAuthenticator;
    }

    /**
     * <p>Sets the Crowd Token Helper to use</p>
     * @param crowdTokenHelper The {@code CrowdHttpTokenHelper} object
     */
    public void setCrowdTokenHelper(CrowdHttpTokenHelper crowdTokenHelper) {
        this.crowdTokenHelper = crowdTokenHelper;
    }

    
    @Override
    public boolean authenticateRequest(ServletContext context,
                                       HttpServletRequest request,
                                       HttpServletResponse response) throws IOException, ServletException {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void restartLoginChallenge(ServletContext context,
                                      HttpServletRequest request,
                                      HttpServletResponse response) throws IOException {
        // TODO Auto-generated method stub

    }
}
