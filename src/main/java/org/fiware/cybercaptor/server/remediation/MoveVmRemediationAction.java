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
import org.fiware.cybercaptor.server.database.Database;

import java.io.File;
import org.jdom2.Element;

public class MoveVmRemediationAction extends RemediationAction {

    // TODO private
    public String vm;
    public String hypervisor;

    /**
     * Create a new train user remediation action
     *
     */
    public MoveVmRemediationAction( String vm, String hypervisor, String costParametersFolder ) throws Exception {

        this.vm = vm;
        this.hypervisor = hypervisor;

        File parametersFile = new File(costParametersFolder + "/" + OperationalCostParameters.FILE_NAME_VM);

        if (parametersFile.exists()) {
            getOperationalCostParameters().loadFromXMLFile(costParametersFolder + "/" + OperationalCostParameters.FILE_NAME_VM);
        }
    }

    private String remediationActionType = "MOVE_VM";

    @Override
    public String toString() {
        return "MoveVmRemediationAction [actionType=" + remediationActionType
                + ", vm=" + vm
                + ", hypervisor=" + hypervisor
                + ", possibleMachines=" + getPossibleMachines() 
                + ", relatedVertex=" + getRelatedVertex() 
                + "]";
    }

    @Override
    public void toXMLElement( Element actionElement, Element typeElement ) {

     	typeElement.setText("move-vm");
	            	
     	Element moveVmElement = new Element("vm-to-move");
     	actionElement.addContent(moveVmElement);
     	moveVmElement.setText(vm);

     	Element currentHypervisorElement = new Element("current-vm-hypervisor");
     	actionElement.addContent(currentHypervisorElement);
     	currentHypervisorElement.setText(hypervisor);
    }

    @Override
    public void applyOnInformationSystem( InformationSystem informationSystem, InformationSystemHost host, Database db ) {
        try {
            informationSystem.existingMachineByNameOrIPAddress(getRelatedVertex().concernedMachine.getName()).setPhysicalHost(null);
        }
        catch( Exception e ) {
            e.printStackTrace();
        }
    }

    @Override
    public SerializableDeployableRemediationAction makeSerializableDeployableRemediationAction(InformationSystemHost host) {

        String remediationAction = "moveVm";

        return new SerializableDeployableRemediationAction( host.getName(), remediationActionType, remediationAction );
    }
}

