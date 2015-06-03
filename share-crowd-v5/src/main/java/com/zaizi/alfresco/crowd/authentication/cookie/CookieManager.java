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

package com.zaizi.alfresco.crowd.authentication.cookie;

import java.io.Serializable;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.zaizi.alfresco.crowd.authentication.cookie.exception.CookieNotFoundException;

/**
 * <p>
 * Class used for managing cookies and for setting and getting serialized objects in cookies
 * </p>
 * 
 * @author Antonio David Perez Morales <aperez@zaizi.com>
 */
public class CookieManager {

    String cookieDomain;

    /**
     * <p>
     * Default constructor
     * </p>
     */
    public CookieManager() {

    }
   
    /**
     * <p>
     * Get the value of a cookie from the http request given its key
     * </p>
     * 
     * @param request
     *            HttpServletRequest used for search the cookie
     * @param key
     *            the cookie key/name
     * @return Serializable if the cookie was found
     * @throws CookieNotFoundException
     *             if cookie value does not exist or it exists but cannot be retrieved
     */
    public Serializable getCookieValue(HttpServletRequest request, String key) throws CookieNotFoundException {
        Cookie[] cookieArray = request.getCookies();
        if (cookieArray != null) {
            for (Cookie cookie : cookieArray) {
                if (cookie.getName().equals(key)) {
                    String cookieValue = cookie.getValue();
                    if (!cookieValue.isEmpty()) {
                        return cookieValue;
                    }
                }
            }
        }
        
        throw new CookieNotFoundException("Cookie "+key+" not found");
    }

    /**
     * <p>
     * Put a cookie value with the given key
     * </p>
     * 
     * @param request
     *            the Http Request
     * @param response
     *            the Http Response
     * @param key
     *            the cookie key
     * @param age
     *            time to live in seconds
     * @param value
     *            the cookie value
     */
    public void putCookieValue(HttpServletRequest request,
                               HttpServletResponse response,
                               String key,
                               int age,
                               Serializable value) {
        putCookieValue(request, response, key, null, null, age, value);
    }

    /**
     * <p>
     * Put a cookie value with the given key
     * </p>
     * 
     * @param request
     *            the Http Request
     * @param response
     *            the Http Response
     * 
     * @param key
     *            the cookie key
     * 
     * @param domain
     *            the domain for the cookie
     * @param path
     *            the path for the cookie
     * @param age
     *            time to live in seconds
     * @param value
     *            the cookie value
     */
    public void putCookieValue(HttpServletRequest request,
                               HttpServletResponse response,
                               String key,
                               String domain, 
                               String path,
                               int age,
                               Serializable value) {

        String cookieValue = null;

        cookieValue = value.toString();
        

        Cookie cookie = new Cookie(key, cookieValue);
        if (path != null && !path.isEmpty()) {
            cookie.setPath(path);
        } else {
            cookie.setPath("/");
        }
        cookie.setMaxAge(age);

        if (domain != null && !domain.isEmpty()) {
            cookie.setDomain(domain);
        }

        response.addCookie(cookie);
    }

    /**
     * <p>
     * Deletes the cookie with the given key in the request from the response
     * </p>
     * 
     * @param request
     *            the Http request
     * @param response
     *            the Http response
     * @param key
     *            the cookie name
     * @param path
     *            the cookie path
     */
    public void destroyCookie(HttpServletRequest request,
                              HttpServletResponse response,
                              String key,
                              String path) {
        Cookie[] cookieArray = request.getCookies();
        if (cookieArray != null) {
            for (Cookie cookie : cookieArray) {
                String name = cookie.getName();
                if (name != null && name.equals(key)) {
                    if (!path.isEmpty()) {
                        cookie.setPath(path);
                    } else {
                        cookie.setPath("/");
                    }
                    cookie.setMaxAge(0);
                    cookie.setValue(null);

                    response.addCookie(cookie);
                }
            }
        }
    }

    /**
     * <p>
     * Deletes the cookie with the given key in the request from the response
     * </p>
     * 
     * @param path
     *            the path for the cookie
     */
    public void destroyCookie(HttpServletRequest request, HttpServletResponse response, String key) {
        destroyCookie(request, response, key, null);
    }
}
