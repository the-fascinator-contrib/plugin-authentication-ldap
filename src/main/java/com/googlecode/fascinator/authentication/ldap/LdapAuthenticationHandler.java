/* 
 * The Fascinator - Common Library
 * Copyright (C) 2008-2009 University of Southern Queensland
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
 */
public class LdapAuthenticationHandler {

	/** Logging */
	private Logger log = LoggerFactory
			.getLogger(LdapAuthenticationHandler.class);

	/** LDAP environment */
	private Hashtable<String, String> env;

	/** LDAP Base DN */
	private String baseDn;

	/** LDAP identifier attribute */
	private String idAttr;

	/** Base LDAP URL */
	private String baseUrl;

	private Map<String, List<String>> objectClassRolesMap;

	/**
	 * Creates an LDAP authenticator for the specified server and base DN, using
	 * the default identifier attribute "uid"
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 */
	public LdapAuthenticationHandler(String baseUrl, String baseDn) {
		this(baseUrl, baseDn, "uid");
	}

	/**
	 * Creates an LDAP authenticator for the specified server, base DN and given
	 * identifier attribute
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 * @param idAttr
	 *            LDAP user identifier attribute
	 */
	public LdapAuthenticationHandler(String baseUrl, String baseDn,
			String idAttr) {
		// Set public variables
		this.baseDn = baseDn;
		this.idAttr = idAttr;
		this.baseUrl = baseUrl;
		// Initialise the LDAP environment
		env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, baseUrl);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
	}

	/**
	 * Creates an LDAP authenticator for the specified server, base DN and given
	 * identifier attribute
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 * @param idAttr
	 *            LDAP user identifier attribute
	 * @param objectClassValue
	 *            Value to look for against the objectClass
	 */
	public LdapAuthenticationHandler(String baseUrl, String baseDn,
			String idAttr, Map<String, List<String>> objectClassRolesMap) {
		this(baseUrl, baseDn, idAttr);
		this.objectClassRolesMap = objectClassRolesMap;
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
			log.warn("Failed LDAP lookup", ne);
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
			// authenticted
			// (and rejected) against.
			Hashtable<String, String> env1 = new Hashtable<String, String>();
			env1.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.ldap.LdapCtxFactory");
			env1.put(Context.PROVIDER_URL, baseUrl);
			env1.put(Context.SECURITY_AUTHENTICATION, "simple");
			DirContext dc = new InitialDirContext(env1);

			SearchControls sc = new SearchControls();
			sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

			// Create the filter
			String filter = "(" + idAttr + "=" + username + ")";

			// Do the search
			NamingEnumeration<SearchResult> ne = dc.search(baseDn, filter, sc);

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
			log.warn("Failed LDAP lookup", ne);
		}
		return "";
	}

	/**
	 * Tries to find the value of the given attribute
	 * 
	 * @param username
	 *            a username
	 * @param attrName
	 *            the name of the attribute to find
	 * @return the value of the attribute, or an empty string
	 */
	public String getAttr(String username, String attrName) {
		try {
			DirContext dc = new InitialDirContext(env);

			SearchControls sc = new SearchControls();
			sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

			String filter = "(" + idAttr + "=" + username + ")";

			NamingEnumeration<SearchResult> ne = dc.search(baseDn, filter, sc);

			if (ne.hasMore()) {
				// Get the attributes
				SearchResult result = ne.next();
				Attributes entry = result.getAttributes();
				// Get the attribute value and return
				Attribute objectClasses = entry.get(attrName);
				String[] strArr = objectClasses.toString().split(":");

				ne.close();
				dc.close();
				return strArr[1].trim();
			} else {
				ne.close();
				dc.close();
			}
		} catch (NamingException ne) {
			log.warn("Failed LDAP lookup", ne);
		}
		return "";
	}

	/**
	 * Searches through the objectClass values and tries to match the given
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
			String[] allVals = getAttr(username, "objectClass").split(",");
			for (int i = 0; i < allVals.length; i++) {
				if (testSubj.equals(allVals[i].trim())) {
					return true;
				}
			}
		} catch (Exception e) {
			// Some problem exists, return false for now
			return false;
		}
		return false;
	}

	public List<String> getRoles(String username) {
		Set<String> roles = new LinkedHashSet<String>();
		String[] allVals = getAttr(username, "objectClass").split(",");
		for (String objectClass : allVals) {
			List<String> roleList = objectClassRolesMap.get(objectClass.trim());
			if (roleList != null) {
				roles.addAll(roleList);
			}
		}
		return new ArrayList<String>(roles);

	}
}
