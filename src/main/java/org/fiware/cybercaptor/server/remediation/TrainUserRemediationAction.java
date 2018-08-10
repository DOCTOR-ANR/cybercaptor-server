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
 * along with FIWARE CyberCAPTOR.                                                       *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/

package org.fiware.cybercaptor.server.remediation;

import org.fiware.cybercaptor.server.attackgraph.Vertex;
import org.fiware.cybercaptor.server.remediation.serializable.SerializableDeployableRemediationAction ;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.database.Database;

import org.jdom2.Element;

public class TrainUserRemediationAction extends RemediationAction {

    // TODO private
    public String userName;

    /**
     * Create a new train user remediation action
     *
     */
    public TrainUserRemediationAction( String userName, String costParametersFolder ) throws Exception {

        this.userName = userName;
    }

    private String remediationActionType = "TRAIN_USER";

    @Override
    public String toString() {
        return "TrainUserRemediationAction [actionType=" + remediationActionType
                + ", userName=" + userName
                + ", possibleMachines=" + getPossibleMachines() 
                + ", relatedVertex=" + getRelatedVertex() 
                + "]";
    }

    @Override
    public void toXMLElement( Element actionElement, Element typeElement ) {

     	typeElement.setText("train-user");
	            	
     	Element userElement = new Element("user-to-train");
     	actionElement.addContent(userElement);
     	userElement.setText(userName);
    }

    @Override
    public void applyOnInformationSystem( InformationSystem informationSystem, InformationSystemHost host, Database db ) {
        // Do nothing
    }

    @Override
    public SerializableDeployableRemediationAction makeSerializableDeployableRemediationAction(InformationSystemHost host) {

        String remediationAction = "";

        return new SerializableDeployableRemediationAction( host.getName(), remediationActionType, remediationAction );
    }
}

