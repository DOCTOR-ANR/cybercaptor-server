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

import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.remediation.serializable.SerializableDeployableRemediationAction ;
import org.jdom2.Element;

/**
 * Class representing a deployable remediation action: a {@link RemediationAction}
 * that can be deployed on a specific host.
 *
 * @author Francois -Xavier Aguessy
 */
public class DeployableRemediationAction {
    /**
     * The remediation action
     */
    private RemediationAction remediationAction;

    /**
     * The host on which the remediation can be deployed.
     */
    private InformationSystemHost host;

    public DeployableRemediationAction() {}

    /**
     * The machine on which the remediation will be deployed
     */
    /**
     * Gets host.
     *
     * @return the host
     */
    public InformationSystemHost getHost() {
        return host;
    }

    /**
     * Sets host.
     *
     * @param host the host to set
     */
    public void setHost(InformationSystemHost host) {
        this.host = host;
    }

    /**
     * To xML element.
     *
     * @return the dom element corresponding to this deployable remediation action
     */
    public Element toXMLElement() {

        Element root = new Element("deployable_remediation");

        Element machineElement = new Element("machine");
        machineElement.setText(getHost().getName() + "");
        root.addContent(machineElement);

        Element actionElement = new Element("action");
        root.addContent(actionElement);

        Element typeElement = new Element("type");
        actionElement.addContent(typeElement);

        remediationAction.toXMLElement( actionElement, typeElement );

        return root;
    }
    
    public SerializableDeployableRemediationAction makeSerializableDeployableRemediationAction() {

        return remediationAction.makeSerializableDeployableRemediationAction( getHost() );
    }

    public void applyOnInformationSystem( InformationSystem informationSystem, Database db ) {
        remediationAction.applyOnInformationSystem( informationSystem, getHost(), db );
    }

    /**
     * Sets remediation action.
     *
     * @param remediationAction the remediation action
     */
    public void setRemediationAction(RemediationAction remediationAction) {
        this.remediationAction = remediationAction;
    }

    /**
     * The remediation action
     *
     * @return the remediation action
     */
    public RemediationAction getRemediationAction() {
        return remediationAction;
    }

    @Override
    public String toString() {
        return remediationAction.toString() + " on " + getHost();
    }
}

