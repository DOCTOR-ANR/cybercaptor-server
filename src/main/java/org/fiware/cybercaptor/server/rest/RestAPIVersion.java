/****************************************************************************************
 * This file is part of FIWARE CyberCAPTOR,                                             *
 * instance of FIWARE Cyber Security Generic Enabler                                    *
 * Copyright (C) 2012-2015  Thales Services S.A.S.,                                     *
 * 20-22 rue Grande Dame Rose 78140 VELIZY-VILACOUBLAY FRANCE                           *
 *                                                                                      *
 * FIWARE CyberCAPTOR is free software; you can redistribute                            *
 * it and/or modify it under the terms of the GNU General Public License                *
 * as published by the Free Software Foundation; either version 3 of the License,       *
 * or (at your option) any later version.                                               *
 *                                                                                      *
 * FIWARE CyberCAPTOR is distributed in the hope                                        *
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied           *
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 * GNU General Public License for more details.                                         *
 *                                                                                      *
 * You should have received a copy of the GNU General Public License                    *
 * along with FIWARE Cyber Security Generic Enabler.                                    *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/

package org.fiware.cybercaptor.server.rest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;


/**
 * Simple REST AttackGraph API to get the REST API version (/rest/version). Useful for tests.
 *
 * @author Francois-Xavier Aguessy
 */
@Path("/version")
public class RestAPIVersion {
	/**
	 * The version of the prototype
	 */
	private static final String version = "4.4";
	
	@GET
	@Produces("text/plain")
	public String getVersion() {
		return version;
	}
	
	@GET
	@Path("/detailed")
	@Produces("text/plain")
	public String getDetailedVersion() {
		return "Cyber Security Generic Enabler v" + version;
	}
}
