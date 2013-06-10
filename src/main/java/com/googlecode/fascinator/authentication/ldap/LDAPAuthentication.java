/*
 * The Fascinator - LDAP Authentication Plugin
 * Copyright (C) 2008-2010 University of Southern Queensland
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


import com.googlecode.fascinator.api.PluginDescription;
import com.googlecode.fascinator.api.authentication.Authentication;
import com.googlecode.fascinator.api.authentication.AuthenticationException;
import com.googlecode.fascinator.api.authentication.User;
import com.googlecode.fascinator.common.JsonSimpleConfig;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * <p>
 * This plugin is a sample plugin on how to manage authentication
 * against an ldap server.
 * </p>
 * 
 * <h3>Configuration</h3> 
 * <p>Standard configuration table:</p>
 * <table border="1">
 * <tr>
 * <th>Option</th>
 * <th>Description</th>
 * <th>Required</th>
 * <th>Default</th>
 * </tr>
 * 
 * <tr>
 * <td>ldap/baseURL</td>
 * <td>URL of the LDAP server</td>
 * <td><b>Yes</b></td>
 * <td>ldap://ldap.uq.edu.au:389</td>
 * </tr>
 * <tr>
 * <td>ldap/baseDN</td>
 * <td>The base Distinguished Name to search under</td>
 * <td><b>Yes</b></td>
 * <td>ou=people,o=The University of Queensland,c=AU</td>
 * </tr>
 * <tr>
 * <td>ldap/ldapSecurityPrincipal</td>
 * <td>Security Principal for non-anonymous binding</td>
 * <td><b>Yes</b></td>
 * <td>cn=JohnDoe,ou=Sample Account,dc=sample,dc=edu,dc=au</td>
 * </tr>
 * <tr>
 * <td>ldap/ldapSecurityCredentials</td>
 * <td>Credentials for ldapSecurityPrincipal</td>
 * <td><b>Yes</b></td>
 * <td>*******</td>
 * </tr>
 * <tr>
 * <td>ldap/idAttribute</td>
 * <td>The name of the attribute for which the username will be searched under</td>
 * <td><b>Yes</b></td>
 * <td>uid</td>
 * </tr>
 * <tr>
 * <td>ldap/ldapRoleAttribute</td>
 * <td>The name of the LDAP attribute that contains the role values</td>
 * <td><b>No</b></td>
 * <td>objectClass</td>
 * </tr>
 * 
 * </table>
 * 
 * <h3>Examples</h3>
 * <ol>
 * <li>
 * Using Internal authentication plugin in The Fascinator
 * 
 * <pre>
 *    "authentication": {
 *            "type": "ldap",
 *            "ldap": {
 *                "baseURL": "ldap://ldap.uq.edu.au:389",
 *                "baseDN": "ou=people,o=The University of Queensland,c=AU",
 *                "ldapSecurityPrincipal": "cn=SomeName,ou=SomeOrgUnit,dn=uq,dn=edu,dn=au",
 *                "ldapSecurityCredentials": "********",
 *                "baseDN": "ou=people,o=The University of Queensland,c=AU",
 *                "idAttribute": "uid"
 *                "ldapRoleAttribute": "objectClass",
 *            }
 *        }
 * </pre>
 * 
 * </li>
 * </ol>
 * 
 * <h3>Wiki Link</h3>
 * <p>
 * None
 * </p>
 *
 * @author Greg Pendlebury
 * and
 * @author Richard Hammond
 */

public class LDAPAuthentication implements Authentication {
    
    /** Logging **/
    @SuppressWarnings("unused")
	private final Logger log = LoggerFactory.getLogger(LDAPAuthentication.class);
    
    /** User object */
    private LDAPUser user_object;
    
    /** Ldap authentication class */
    private LdapAuthenticationHandler ldapAuth;

    @Override
    public String getId() {
        return "ldap";
    }

    @Override
    public String getName() {
        return "LDAP Authentication";
    }

    /**
     * Gets a PluginDescription object relating to this plugin.
     *
     * @return a PluginDescription
     */
    @Override
    public PluginDescription getPluginDetails() {
        return new PluginDescription(this);
    }

    /**
     * Initialisation of LDAP Authentication plugin
     * 
     * @throws AuthenticationException if fails to initialise
     */
    @Override
    public void init(String jsonString) throws AuthenticationException {
        try {
            setConfig(new JsonSimpleConfig(jsonString));
        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationException(e);
        } catch (IOException e) {
            throw new AuthenticationException(e);
        }
    }

    @Override
    public void init(File jsonFile) throws AuthenticationException {
        try {
            setConfig(new JsonSimpleConfig(jsonFile));
        } catch (IOException ioe) {
            throw new AuthenticationException(ioe);
        }
    }

    /**
     * Set default configuration
     * 
     * @param config JSON configuration
     * @throws IOException if fails to initialise
     */
    private void setConfig(JsonSimpleConfig config) throws IOException {
        user_object = new LDAPUser();
        String url = config.getString(null, "authentication", "ldap", "baseURL");
        String baseDN = config.getString(null, "authentication", "ldap", "baseDN");
        String idAttribute = config.getString(null, "authentication", "ldap", "idAttribute");
        String secPrinc = config.getString(null, "authentication", "ldap", "ldapSecurityPrincipal");
        String secCreds = config.getString(null, "authentication", "ldap", "ldapSecurityCredentials");
        
        //Need to get these values from somewhere, ie the config file passed in
        ldapAuth = new LdapAuthenticationHandler(url, baseDN, secPrinc, secCreds, "objectClass", idAttribute);
    }

    @Override
    public void shutdown() throws AuthenticationException {
        // Don't need to do anything
    }

    /**
     * Tests the user's username/password validity.
     *
     * @param username The username of the user logging in.
     * @param password The password of the user logging in.
     * @return A user object for the newly logged in user.
     * @throws AuthenticationException if there was an error logging in.
     */
    @Override
    public User logIn(String username, String password) throws AuthenticationException {
        //Check to see if users authorised.
        if (ldapAuth.authenticate(username,password)) {
            //Return a user object.
            return getUser(username);
        } else {
            throw new AuthenticationException("Invalid password or username.");
        }
    }

    /**
     * Optional logout method if the implementing class wants
     * to do any post-processing.
     *
     * @param username The username of the logging out user.
     * @throws AuthenticationException if there was an error logging out.
     */
    @Override
    public void logOut(User user) throws AuthenticationException {
        // Do nothing
    }

    /**
     * Method for testing if the implementing plugin allows
     * the creation, deletion and modification of users.
     *
     * @return true/false reponse.
     */
    @Override
    public boolean supportsUserManagement() {
        return false;
    }

    /**
     * Describe the metadata the implementing class
     * needs/allows for a user.
     *
     * TODO: This is a placeholder of possible later SQUIRE integration.
     *
     * @return TODO: possibly a JSON string.
     */
    @Override
    public String describeUser() {
        return user_object.describeMetadata();
    }

    /**
     * Create a user.
     *
     * @param username The username of the new user.
     * @param password The password of the new user.
     * @return A user object for the newly created in user.
     * @throws AuthenticationException if there was an error creating the user.
     */
    @Override
    public User createUser(String username, String password) throws AuthenticationException {
        //Don't think you can create a user in LDAP, so throw an error (for now).
        throw new AuthenticationException("Cannot create a new LDAP user.");
    }

    /**
     * Delete a user.
     *
     * @param username The username of the user to delete.
     * @throws AuthenticationException if there was an error during deletion.
     */
    @Override
    public void deleteUser(String username) throws AuthenticationException {
        //Don't think you can delete a user in LDAP, so throw an error (for now).
        throw new AuthenticationException("Cannot delete an LDAP user.");
    }

    /**
     * A simplified method alternative to modifyUser() if the implementing
     * class wants to just allow password changes.
     *
     * @param username The user changing their password.
     * @param password The new password for the user.
     * @throws AuthenticationException if there was an error changing the password.
     */
    @Override
    public void changePassword(String username, String password) throws AuthenticationException {
        //Don't think you can change the password in LDAP, so throw an error (for now).
        throw new AuthenticationException("Cannot change password in LDAP.");
    }

    /**
     * Modify one of the user's properties. Available properties should match
     * up with the return value of describeUser().
     *
     * @param username The user being modified.
     * @param property The user property being modified.
     * @param newValue The new value to be assigned to the property.
     * @return An updated user object for the modifed user.
     * @throws AuthenticationException if there was an error during modification.
     */
    @Override
    public User modifyUser(String username, String property, String newValue)
            throws AuthenticationException {
        throw new AuthenticationException("This class does not support user modification.");
    }
    @Override
    public User modifyUser(String username, String property, int newValue)
            throws AuthenticationException {
        throw new AuthenticationException("This class does not support user modification.");
    }
    @Override
    public User modifyUser(String username, String property, boolean newValue)
            throws AuthenticationException {
        throw new AuthenticationException("This class does not support user modification.");
    }

    /**
     * Returns a User object if the implementing class supports
     * user queries without authentication.
     *
     * @param username The username of the user required.
     * @return An user object of the requested user.
     * @throws AuthenticationException if there was an error retrieving the object.
     */
    @Override
    public User getUser(String username) throws AuthenticationException {
        //Get a new user object and try to find the users common name
        user_object = new LDAPUser();
        String cn = ldapAuth.getAttr(username,"cn");
        if (cn.equals("")) {
            //Initialise the user with displayname the same as the username
            user_object.init(username);
        } else {
            //Initialise the user with different displayname and username
            user_object.init(username,cn);
        }
        return user_object;
    }

    /**
     * Returns a list of users matching the search.
     *
     * @param search The search string to execute.
     * @return A list of usernames (String) that match the search.
     * @throws AuthenticationException if there was an error searching.
     */
    @Override
    public List<User> searchUsers(String search) throws AuthenticationException {
        //Just return an empty list for now
        List<User> found = new ArrayList<User>();
        return found;
    }

}
