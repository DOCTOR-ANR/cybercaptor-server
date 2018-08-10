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
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.remediation.cost.OperationalCostParameters;
import org.fiware.cybercaptor.server.remediation.serializable.SerializableDeployableRemediationAction ;
import org.fiware.cybercaptor.server.database.Database;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.jdom2.Element;

/**
 * Class that represents a remediation action to correct a vulnerability
 * For example : applying a patch, training a user, deploying a firewall or snort rule,...
 * This remediation may be applicable on several machines
 *
 * @author Francois -Xavier Aguessy
 */
public abstract class RemediationAction {

    /**
     * The possible machines on which the remediation can be deployed
     */
    private List<InformationSystemHost> possibleMachines = new ArrayList<InformationSystemHost>();
    /**
     * The vertex in the attack graph related to this remediation
     */
    private Vertex relatedVertex;
    /**
     * The parameters used to compute the operational cost for this remediation action
     */
    private OperationalCostParameters operationalCostParameters = new OperationalCostParameters();

    /**
     * Create a new remediation action
     *
     * @param actionType           the type of remediation action
     * @param costParametersFolder the cost parameters folder
     * @throws Exception the exception
     */
    public RemediationAction() { }

    /**
     * Gets action type.
     *
     * @return the action type
     */
    // TODO public abstract ActionType getActionType();

    /**
     * Gets possible machines.
     *
     * @return the possible machines
     */
    public List<InformationSystemHost> getPossibleMachines() {
        return possibleMachines;
    }

    /**
     * Sets possible machines.
     *
     * @param possibleMachines the possible machines
     */
    public void setPossibleMachines(List<InformationSystemHost> possibleMachines) {
        this.possibleMachines = possibleMachines;
    }

    /**
     * Gets related vertex.
     *
     * @return the related vertex
     */
    public Vertex getRelatedVertex() {
        return relatedVertex;
    }

    /**
     * Sets related vertex.
     *
     * @param relatedVertex the related vertex
     */
    public void setRelatedVertex(Vertex relatedVertex) {
        this.relatedVertex = relatedVertex;
    }

    /**
     * Gets operational cost parameters.
     *
     * @return the operational cost parameters
     */
    public OperationalCostParameters getOperationalCostParameters() {
        return operationalCostParameters;
    }

    /**
     * Sets operational cost parameters.
     *
     * @param operationalCostParameters the operational cost parameters
     */
    public void setOperationalCostParameters(OperationalCostParameters operationalCostParameters) {
        this.operationalCostParameters = operationalCostParameters;
    }

    /**
     * Gets remediation cost.
     *
     * @return the remediation cost
     */
    public double getRemediationCost() {
        return Math.round(getOperationalCostParameters().getRemediationCost() * 100.0) / 100.0;
    }

    /**
     * Gets test cost.
     *
     * @return the test cost (operationnal cost)
     */
    public double getTestCost() {
        OperationalCostParameters param = getOperationalCostParameters(); //Shorter to write...
        double res = (param.getDeploymentDuration()
                + param.getBusinessApplicationsTestsDuration()
                + param.getRemediationUninstallDuration()) * param.getSkillRateTests() * param.getWorkCost();
        return Math.round(res * 100.0) / 100.0;
    }

    /**
     * Gets deployment cost.
     *
     * @return the deployment costs
     */
    public double getDeploymentCost() {
        OperationalCostParameters param = getOperationalCostParameters(); //Shorter to write...

        double deploymentCost = param.getDeploymentDuration() * param.getSkillRateDeployment() * param.getWorkCost();
        double testProductionCost = param.getBusinessApplicationsTestsDuration() * param.getSkillRateTests() * param.getWorkCost();
        double indisponibilityCost = 0;

        return Math.round((deploymentCost + testProductionCost + indisponibilityCost) * 100.0) / 100.0;
    }

    /**
     * Gets restart cost.
     *
     * @return the restart cost
     */
    public double getRestartCost() {
        OperationalCostParameters param = getOperationalCostParameters(); //Shorter to write...

        double restartCost = param.getRestartCost();

        return Math.round(restartCost * 100.0) / 100.0;
    }

    /**
     * Gets maintenance cost.
     *
     * @return the maintenance cost (per year)
     */
    public double getMaintenanceCost() {
        OperationalCostParameters param = getOperationalCostParameters(); //Shorter to write...


        double res = param.getUsedPower() * param.getComputationPowerCost() +
                param.getUsedStorage() * param.getStorageCost() +
                param.getMaintenanceDuration() * param.getWorkCost() * param.getSkillRateMaintenance();
        return Math.round(res * 100.0) / 100.0;
    }

    /**
     * Gets operational cost.
     *
     * @return the cost to deploy the remediation action
     */
    public double getOperationalCost() {
        return Math.round((getRemediationCost() + getMaintenanceCost() + getRestartCost() + getDeploymentCost() + getTestCost()) * 100.0) / 100.0;
    }

    public abstract void toXMLElement( Element actionElement, Element typeElement );

    public abstract void applyOnInformationSystem( InformationSystem informationSystem, InformationSystemHost host, Database db );

    public abstract SerializableDeployableRemediationAction makeSerializableDeployableRemediationAction(InformationSystemHost host);

    /**
     * The possible types of remediation
     */
    // TODO
    /*public static enum ActionType {
        **
         * Applying a patch
         *
        APPLY_PATCH, **
         * Deploying a snort rule
         *
        DEPLOY_SNORT_RULE, **
         * Training a user
         *
        TRAIN_USER, **
         * Deploying a firewall rule
         *
        DEPLOY_FIREWALL_RULE, **
         * Move a VM
         *
        MOVE_VM, **
         * Move a VM to another domain
         *
        MOVE_VM_DOMAIN
    }
    */
}

