# LDAP Authentication Plugin for The Fascinator #

This plugin allows authentication against an LDAP server for The fascinator platform.

## Configuration ##

	"authentication": {
		"type": "ldap",
		"ldap": {
			"baseURL": "ldap://localhost:389",
			"baseDN": "ou=people,o=Sample org,c=AU",
			"ldapSecurityPrincipal": "cn=JohnDoe,ou=Some Account,dc=sample,dc=edu,dc=au"
			"ldapSecurityCredentials": "******"
			"idAttribute": "uid"
		}
	}
 
**baseURL**

The URL of the LDAP server.

**baseDN**

The base Distinguished Name to search under.

**idAttribute**

The name of the attribute for which the username will be searched under. This
will be appended to the end of the baseDN when querying the LDAP server.  Using
the example configuration above the query string will be:

	ou=people,o=Sample org,c=AU,uid=specifiedUsername
	
**ldapSecurityPrincipal**

The Security Principal of the service account used to bind to the LDAP server.
(Leave empty to bind anonymously.)

**ldapSecurityCredentials**

Credentials for the service account used to bind to the LDAP server.
(Leave empty to bind anonymously.)



