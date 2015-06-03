#alfresco-crowd-sso
Alfresco 5 plugin to provide Single Sign On (SSO) with Atlassian Crowd. This Module authenticates users in Alfresco using Atlassian Crowd
& allows to authenticate users against Atlassian Crowd which means that if you are already logged in another Crowd-managed application, you will be logged in automatically in Alfresco.

The module consists in two components:

	1) Alfresco component: New authentication subsystem for Atlassian Crowd and two WebScripts used by Share (validate and get a Crowd token)
	2) Share component: Send authentication requests to Alfresco. Uses the Crowd token if exists to logging in the user automatically. Developed as Java Filter

##Installation
In order to install the module,

* Build the code using
`mvn package`
* copy the amp files to the right place (amps folder for Alfresco and amps-share folder for Share)
* Install modules by running `./apply_amps.sh` script

##Configurations

* Add/Modify below properties in `alfresco-global.properties`

		* application.name: The application name configured in Crowd
		* application.password: The application password configured in Crowd
		* crowd.base.url: The URL of the Crowd server. eg : http://localhost:8095/crowd/
		* authentication.chain=crowd1:crowd,[Other authentication subsystems if needed]
		* crowd.xff.address : The 'X-Forward-For' address. eg : proxy ip address.

* Add below filter configurations in share `web.xml` (before the default Authentication Filter)

		<filter>
			<description>Crowd SSO authentication filter.</description>
			<filter-name>crowd-filter</filter-name>
			<filter-class>com.zaizi.alfresco.crowd.authentication.filter.CrowdSSOFilter</filter-class>
		</filter>
		
		<filter-mapping>	
			<filter-name>crowd-filter</filter-name>
			<url-pattern>/page/*</url-pattern>
		</filter-mapping>
		<filter-mapping>
			<filter-name>crowd-filter</filter-name>
			<url-pattern>/p/*</url-pattern>
		</filter-mapping>
		<filter-mapping>
			<filter-name>crowd-filter</filter-name>
			<url-pattern>/proxy/*</url-pattern>
		</filter-mapping>