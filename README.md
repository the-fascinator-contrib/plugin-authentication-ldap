# LDAP Authentication Plugin for The Fascinator #

This plugin allows authentication against an LDAP server for The fascinator platform.

## Configuration ##

	"authentication": {
		"type": "ldap",
		"ldap": {
			"baseURL": "ldap://localhost:389",
			"baseDN": "ou=people,o=Sample org,c=AU",
			"idAttribute": "uid"
		}
	}
 
**baseURL**

The URL of the LDAP server.

**baseDN**

The base Distinguished Name to search under.

**idAttribute**

The name of the attribute for which the username will be searched under. This will be appended to the end of the baseDN when querying the LDAP server.
Using the example configuration above the query string will be:

	ou=people,o=Sample org,c=AU,uid=specifiedUsername

