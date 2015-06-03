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

package com.zaizi.alfresco.crowd;

import java.util.Properties;

import org.springframework.beans.factory.InitializingBean;

import com.atlassian.crowd.service.client.ClientPropertiesImpl;

/**
 * <p>Alfresco Client Properties class</p>
 * <p>Used by Rest Crowd Client to obtain the properties to communicate with Atlassian Crowd</p>
 * 
 * @author Antonio David Perez Morales <aperez@zaizi.com>
 *
 */
public class AlfrescoClientProperties extends ClientPropertiesImpl implements InitializingBean{

   /**
    * <p>The alfresco global properties bean</p>
    */
   private Properties alfrescoGlobalProperties;

   /**
    * <p>Default constructor</p>
    */
   public AlfrescoClientProperties() {
       this.alfrescoGlobalProperties = new Properties();
   }

   /**
    * <p>Set the alfresco global properties bean</p>
    * 
    * @param alfrescoGlobalProperties the alfresco global properties bean
    */
   public void setAlfrescoGlobalProperties(Properties alfrescoGlobalProperties) {
       this.alfrescoGlobalProperties = alfrescoGlobalProperties;
   }
   
   /**
    * <p>Updates the Crowd properties once the bean has been initialized</p>
    */
   @Override
   public void afterPropertiesSet() throws Exception {
       this.updateProperties(this.alfrescoGlobalProperties);
   }
}
