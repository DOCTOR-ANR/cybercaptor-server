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
import org.fiware.cybercaptor.server.remediation.cost.OperationalCostParameters;
import org.fiware.cybercaptor.server.remediation.serializable.SerializableDeployableRemediationAction ;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.vulnerability.Vulnerability;
import org.fiware.cybercaptor.server.database.Database;

import java.io.File;
import java.util.List;
import java.util.ArrayList;
import org.jdom2.Element;

public class PatchRemediationAction extends RemediationAction {

    // TODO private
    public List<Patch> patches = new ArrayList<Patch>();

    /**
     * Create a new train user remediation action
     *
     */
    public PatchRemediationAction( String costParametersFolder ) throws Exception {

        File parametersFile = new File(costParametersFolder + "/" + OperationalCostParameters.FILE_NAME_PATCH);

        if (parametersFile.exists()) {
            getOperationalCostParameters().loadFromXMLFile(costParametersFolder + "/" + OperationalCostParameters.FILE_NAME_PATCH);
        }
    }

    private String remediationActionType = "APPLY_PATCH";


    @Override
    public String toString() {
        return "PatchRemediationAction [actionType=" + remediationActionType
                + ", patches=" + patches
                + ", possibleMachines=" + getPossibleMachines() 
                + ", relatedVertex=" + getRelatedVertex() 
                + "]";
    }

    @Override
    public void toXMLElement( Element actionElement, Element typeElement ) {

        typeElement.setText("patch");

        Element patchsElement = new Element("patchs");
        actionElement.addContent(patchsElement);

	for( Patch patch : patches ) {
            Element patchElement = new Element("patch");
	    patchElement.setText(
		"name:"  + patch.getName() +
		",link:" + patch.getLink() +
		",desc:" + patch.getDescription() 
	    );
	    
            patchsElement.addContent(patchElement);
        }
    }

    @Override
    public void applyOnInformationSystem( InformationSystem informationSystem, InformationSystemHost host, Database db ) {

        for( Patch patch : patches ) {

            try {
                List<Vulnerability> correctedVulnerabilities = patch.getCorrectedVulnerabilities(db.getConn());
                informationSystem.existingMachineByNameOrIPAddress(host.getName()).correctVulnerabilities(correctedVulnerabilities);
            }
            catch( Exception e ) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public SerializableDeployableRemediationAction makeSerializableDeployableRemediationAction(InformationSystemHost host) {

        StringBuilder patchStringBuilder = new StringBuilder();
        String sep = "";

        for( Patch patch : patches ) {
            patchStringBuilder.append(sep);
            sep = "|";
            patchStringBuilder.append(patch.getLink());
        }

        String remediationAction = patchStringBuilder.toString();

        return new SerializableDeployableRemediationAction( host.getName(), remediationActionType, remediationAction );
    }
}

