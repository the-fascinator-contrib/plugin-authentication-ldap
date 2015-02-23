/*
 * The Fascinator - File System User
 * Copyright (C) 2010 University of Southern Queensland
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

import com.googlecode.fascinator.common.authentication.GenericUser;

/**
 * A ldap user object
 *
 * @author Richard Hammond
 */
public class LDAPUser extends GenericUser {
    public String displayName;

    /**
     * Retrieves how the user should be shown on-screen.
     * 
     * @return The value of the property
     */
    @Override
    public String realName() {
        return displayName;
    }

	/**
	 * Plugin initialisation
	 * 
	 * @param user User name
	 */
    public void init(String user) {
        setUsername(user);
        displayName = user;
    }

    /**
     * Plugin initialisation with alternative displayName
     *
     * @param user Username
     * @param displayName Displayname (different to username)
     */
    public void init(String user, String displayName) {
        init(user);
        this.displayName = displayName;
    }
}
