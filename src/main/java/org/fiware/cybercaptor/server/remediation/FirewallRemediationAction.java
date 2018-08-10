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
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.database.Database;

import java.io.File;
import org.jdom2.Element;

public class FirewallRemediationAction extends RemediationAction {

    // TODO private
    public FirewallRule rule;

    /**
     * Create a new train user remediation action
     *
     */
    public FirewallRemediationAction( String costParametersFolder ) throws Exception {

        File parametersFile = new File(costParametersFolder + "/" + OperationalCostParameters.FILE_NAME_FIREWALL_RULE);

        if (parametersFile.exists()) {
            getOperationalCostParameters().loadFromXMLFile(costParametersFolder + "/" + OperationalCostParameters.FILE_NAME_FIREWALL_RULE);
        }
    }

    private String remediationActionType = "DEPLOY_FIREWALL_RULE";

    @Override
    public String toString() {
        return "FirewallRemediationAction [actionType=" + remediationActionType 
                + ", rule=" + rule
                + ", possibleMachines=" + getPossibleMachines() 
                + ", relatedVertex=" + getRelatedVertex() 
                + "]";
    }

    @Override
    public void toXMLElement( Element actionElement, Element typeElement ) {

        typeElement.setText("firewall-rule");

        Element fwRuleElement = new Element("rule");
        fwRuleElement.setText(rule.toIptablesAddRule());
        actionElement.addContent(fwRuleElement);
    }

    @Override
    public void applyOnInformationSystem( InformationSystem informationSystem, InformationSystemHost host, Database db ) {
    
        try {
            if (rule.getTable() == FirewallRule.Table.INPUT) {

                informationSystem.existingMachineByNameOrIPAddress(host.getName()).getInputFirewallRulesTable().getRuleList().add(0, rule);

            } else if (rule.getTable() == FirewallRule.Table.OUTPUT) {

                informationSystem.existingMachineByNameOrIPAddress(host.getName()).getOutputFirewallRulesTable().getRuleList().add(0, rule);
            }
        }
        catch( Exception e ) {
            e.printStackTrace();
        }
    }

    @Override
    public SerializableDeployableRemediationAction makeSerializableDeployableRemediationAction(InformationSystemHost host) {

        String remediationAction = rule.toString();

        return new SerializableDeployableRemediationAction( host.getName(), remediationActionType, remediationAction );
    }
}

