/* 
 * The Fascinator - Common Library
 * Copyright (C) 2008-2009 University of Southern Queensland
 * Copyright (C) 2012 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package com.googlecode.fascinator.authentication.ldap;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Very simple LDAP authentication Handler
 * 
 * @author Oliver Lucido and
 * @author Richard Hammond
 * @author Mike Jones
 */
public class LdapAuthenticationHandler {

	/** Logging */
	private Logger log = LoggerFactory
			.getLogger(LdapAuthenticationHandler.class);

	/** LDAP environment */
	private Hashtable<String, String> env;

	/** LDAP Base DN */
	private String baseDn;

	/** Name of the LDAP attribute that defines the role */
	private String ldapRoleAttr;

	/** LDAP identifier attribute */
	private String idAttr;

	/** Base LDAP URL */
	private String baseUrl;
  
	/* LDAP security principal */
	private String ldapSecurityPrincipal;
  
	/* LDAP security credentials */
	private String ldapSecurityCredentials;

	/** Prefix for the LDAP query filter */
	private String filterPrefix = "";

	/** Suffix for the LDAP query filter */
	private String filterSuffix = "";

	private Map<String, List<String>> ldapRolesMap;

	/**
	 * Creates an LDAP authenticator for the specified server and base DN, using
	 * the default identifier attribute "uid"
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 */
	public LdapAuthenticationHandler(String baseUrl, String baseDn, String ldapSecurityPrincipal, String ldapSecurityCredentials) {
		this(baseUrl, baseDn, ldapSecurityPrincipal, ldapSecurityCredentials, "objectClass", "uid");
	}

	/**
	 * Creates an LDAP authenticator for the specified server, base DN and given
	 * identifier attribute
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 * @param ldapSecurityPrincipal
	 *            LDAP Security Principal
	 * @param ldapSecurityCredentials
	 *            Credentials for Security Principal
	 * @param ldapRoleAttr
	 *            Name of the LDAP attribute that defines the role
	 * @param idAttr
	 *            LDAP user identifier attribute
	 */
	public LdapAuthenticationHandler(String baseUrl, String baseDn,
      		String ldapSecurityPrincipal, String ldapSecurityCredentials,
		String ldapRoleAttr, String idAttr) {
		// Set public variables
		this.baseDn = baseDn;
		this.idAttr = idAttr;
		this.ldapRoleAttr = ldapRoleAttr;
		this.baseUrl = baseUrl;
		this.ldapSecurityPrincipal = ldapSecurityPrincipal;
		this.ldapSecurityCredentials = ldapSecurityCredentials;
		// Initialise the LDAP environment
		env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, baseUrl);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		if (!ldapSecurityPrincipal.equals("") ) {
			env.put(Context.SECURITY_PRINCIPAL, ldapSecurityPrincipal);
 			env.put(Context.SECURITY_CREDENTIALS, ldapSecurityCredentials);
		}

	}

	/**
	 * Creates an LDAP authenticator for the specified server, base DN and given
	 * identifier attribute
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
 	 * @param ldapSecurityPrincipal
	 *            LDAP Security Principal
	 * @param ldapSecurityCredentials
	 *            Credentials for Security Principal
	 * @param ldapRoleAttr
	 *            Name of the LDAP attribute that defines the role
	 * @param idAttr
	 *            LDAP user identifier attribute
	 * @param ldapRolesMap
	 *            Maps relevant LDAP roles to Fascinator roles
	 */
	public LdapAuthenticationHandler(String baseUrl, String baseDn, 
			String ldapSecurityPrincipal,
			String ldapSecurityCredentials,
      			String ldapRoleAttr,
			String idAttr, Map<String, List<String>> ldapRolesMap) {
		this(baseUrl, baseDn, ldapSecurityPrincipal, ldapSecurityCredentials, ldapRoleAttr, idAttr);
		this.ldapRolesMap = ldapRolesMap;
	}

	/**
	 * Creates an LDAP authenticator for the specified server, base DN and given
	 * identifier attribute
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
 	 * @param ldapSecurityPrincipal
	 *            LDAP Security Principal
	 * @param ldapSecurityCredentials
	 *            Credentials for Security Principal
	 * @param ldapRoleAttr
	 *            Name of the LDAP attribute that defines the role
	 * @param idAttr
	 *            LDAP user identifier attribute
	 * @param ldapRolesMap
	 *            Maps relevant LDAP roles to Fascinator roles
	 */
	public LdapAuthenticationHandler(String baseUrl, String baseDn, 
			String ldapSecurityPrincipal,
 			String ldapSecurityCredentials,
      			String ldapRoleAttr,
			String idAttr, String filterPrefix, String filterSuffix, Map<String, List<String>> ldapRolesMap) {
		this(baseUrl, baseDn, ldapSecurityPrincipal, ldapSecurityCredentials, ldapRoleAttr, idAttr, ldapRolesMap);
		this.filterPrefix = filterPrefix;
		this.filterSuffix = filterSuffix;
	}

	/**
	 * Attempts to authenticate user credentials with the LDAP server
	 * 
	 * @param username
	 *            a username
	 * @param password
	 *            a password
	 * @param dn
	 *            if precise dn known, otherwise should be empty string
	 * @return <code>true</code> if authentication was successful,
	 *         <code>false</code> otherwise
	 */
	private boolean doAuthenticate(String username, String password, String dn) {
		try {
			String principal;
			// Either form the dn, or use the given one
			if (dn.equals("")) {
				principal = String.format("%s=%s,%s", idAttr, username, baseDn);
			} else {
				principal = dn;
			}
			env.put(Context.SECURITY_PRINCIPAL, principal);
			env.put(Context.SECURITY_CREDENTIALS, password);
			DirContext ctx = new InitialDirContext(env);
			ctx.lookup(principal);
			ctx.close();
			return true;
		} catch (NamingException ne) {
			log.warn("Failed LDAP lookup doAuthenticate", ne);
		}
		return false;
	}

	/**
	 * Tries to authenticate user by using default settings, otherwise searches
	 * for the DN of the user
	 * 
	 * @param username
	 *            a username
	 * @param password
	 *            a password
	 * @return <code>true</code> if authentication was successful,
	 *         <code>false</code> otherwise
	 */
	public boolean authenticate(String username, String password) {
		// Test with default settings
		if (doAuthenticate(username, password, "")) {
			return true;
		} else {
			// Now try same after searching for the dn
			return doAuthenticate(username, password, getDN(username));
		}
	}

	/**
	 * Tries to find the dn of the given username so that a user can be
	 * authenticated.
	 * 
	 * @param username
	 *            a username
	 * @return The DN of the user if successful, otherwise an empty string.
	 */
	private String getDN(String username) {
		try {
			// Create a new environment since the original one has probably been
			// authenticated (and rejected) against.
			Hashtable<String, String> env1 = new Hashtable<String, String>();
			env1.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.ldap.LdapCtxFactory");
			env1.put(Context.PROVIDER_URL, baseUrl);
			env1.put(Context.SECURITY_AUTHENTICATION, "simple");
			DirContext dc = new InitialDirContext(env1);

			SearchControls sc = new SearchControls();
			sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

			// Create the filter
			String filter = "(" + filterPrefix + idAttr + "=" + username + filterSuffix + ")";

			// Do the search
			NamingEnumeration<SearchResult> ne = dc.search(baseDn, filter, sc);
			log.trace(String.format("LDAP search, baseDn: %s, filter: %s", baseDn, filter));

			if (ne.hasMore()) {
				SearchResult sr = ne.next();
				ne.close();
				dc.close();
				return sr.getNameInNamespace();
			} else {
				ne.close();
				dc.close();
			}
		} catch (NamingException ne) {
			log.warn("Failed LDAP lookup getDN", ne);
		}
		return "";
	}

	/**
	 * Performs a search of LDAP
	 * @param username The username to be used in the search
	 * @param dc The directory context to use for the search
	 * @return An enumeration containing the search results
	 * @throws NamingException
	 */
	private NamingEnumeration<SearchResult> performLdapSearch(String username, DirContext dc) throws NamingException {
		SearchControls sc = new SearchControls();
		sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

		String filter = "(" + filterPrefix + idAttr + "=" + username + filterSuffix + ")";

		NamingEnumeration<SearchResult> ne = dc.search(baseDn, filter, sc);
		log.trace(String.format("performing LDAP search using baseDn: %s, filter: %s", baseDn, filter));
		return ne;
	}

	/**
	 * Get the value of an attribute from a search result
	 * @param attrName The name of the attribute that we're interested in
	 * @param sr The search result
	 * @return The attribute value
	 * @throws NamingException
	 */
	private String getAttrValue(String attrName, SearchResult sr) throws NamingException {
		// Get all attributes
		Attributes entry = sr.getAttributes();

		// Get the attribute value and return
		Attribute attrValues = entry.get(attrName);
		String[] strArr = attrValues.toString().split(":");
		return strArr[1].trim();
	}

	/**
	 * Tries to find the value of the given attribute.
	 * Note that this method only uses the first search result.
	 * 
	 * @param username
	 *            a username
	 * @param attrName
	 *            the name of the attribute to find
	 * @return the value of the attribute, or an empty string
	 */
	public String getAttr(String username, String attrName) {
		String val = "";
		try {
			DirContext dc = new InitialDirContext(env);
			NamingEnumeration<SearchResult> ne = performLdapSearch(username, dc);

			if (ne.hasMore()) {
				val = getAttrValue(attrName, ne.next());
			}

			ne.close();
			dc.close();
		} catch (NamingException ne) {
			log.warn("Failed LDAP lookup getAttr", ne);
			log.warn("username:", username);
			log.warn("attrName:", attrName);
		}

		log.trace(String.format("getAttr search result: %s", val));
		return val;
	}

	/**
	 * Tries to find the value(s) of the given attribute.
	 * Note that this method uses all search results.
	 * 
	 * @param username
	 *            a username
	 * @param attrName
	 *            the name of the attribute to find
	 * @return a list of values for the attribute, or an empty list
	 */
	public List<String> getAllAttrs(String username, String attrName) {
		List<String> resultList = new ArrayList<String>();

		try {
			DirContext dc = new InitialDirContext(env);
			NamingEnumeration<SearchResult> ne = performLdapSearch(username, dc);

			while (ne.hasMore()) {
				resultList.add(getAttrValue(attrName, ne.next()));
			}

			ne.close();
			dc.close();
		} catch (NamingException ne) {
			log.warn("Failed LDAP lookup getAllAttrs" + username, ne);
		}

			log.trace("getAllAttrs search result: " + resultList);
		if (log.isTraceEnabled()) {
			log.trace("getAllAttrs search result: " + resultList);
		}

		return resultList;
	}

	/**
	 * Searches through the role attribute values and tries to match the given
	 * string.
	 * 
	 * @param username
	 *            a username
	 * @param testSubj
	 *            the string to look for
	 * @return <code>true</code> if string was found <code>false</code>
	 *         otherwise
	 */
	public boolean testIfInObjectClass(String username, String testSubj) {
		try {
			List<String> attrValues = getAllAttrs(username, ldapRoleAttr);
			for (String attrValue : attrValues) {
				String[] allVals = attrValue.split(",");
				for (int i = 0; i < allVals.length; i++) {
					if (testSubj.equals(allVals[i].trim())) {
						return true;
					}
				}
			}
		} catch (Exception e) {
			// Some problem exists, return false for now
			return false;
		}
		return false;
	}

	/**
	 * Get the list of roles that the user is a member of. Maps LDAP roles to Fascinator roles.
	 * @param username The username that identifies the user
	 * @return A list of Fascinator role names
	 */
	public List<String> getRoles(String username) {
		Set<String> roles = new LinkedHashSet<String>();
		List<String> attrValues = getAllAttrs(username, ldapRoleAttr);
		for (String attrValue : attrValues) {
			String[] allVals = attrValue.split(",");
			for (String objectClass : allVals) {
				List<String> roleList = ldapRolesMap.get(objectClass.trim());
				if (roleList != null) {
					roles.addAll(roleList);
				}
			}
		}

		log.trace(String.format("getRoles found %d roles for username: %s", roles.size(), username));
		return new ArrayList<String>(roles);

	}
}
