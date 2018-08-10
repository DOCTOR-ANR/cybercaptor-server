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
package org.fiware.cybercaptor.server.attackgraph;

import org.fiware.cybercaptor.server.attackgraph.Vertex.VertexType;
import org.fiware.cybercaptor.server.attackgraph.fact.DatalogCommand;
import org.fiware.cybercaptor.server.attackgraph.fact.Fact;
import org.fiware.cybercaptor.server.attackgraph.fact.Fact.FactType;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.informationsystem.Service;
import org.fiware.cybercaptor.server.informationsystem.graph.InformationSystemGraph;
import org.fiware.cybercaptor.server.remediation.*;
import org.fiware.cybercaptor.server.topology.Topology;
import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule.Action;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule.Protocol;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule.Table;
import org.fiware.cybercaptor.server.topology.asset.component.PortRange;
import org.fiware.cybercaptor.server.vulnerability.Vulnerability;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.input.SAXBuilder;

import java.io.FileInputStream;
import java.sql.Connection;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class used to represent an attack path.
 * An attack path is in fact a special attack graph with several leaves and one goal
 *
 * @author Francois-Xavier Aguessy
 */
public class AttackPath extends MulvalAttackGraph implements Cloneable {

    /**
     * The ID
     */
	public double id;
	
	/**
     * The scoring of the attack path (should be between 0 and 1)
     */
    public double scoring = 0;
    /**
     * The goal of the attacker
     */
    Vertex goal = null;
    
    /**
     * The target of this attack path (MulVAL fact)
     */
    public String targetString = null;

    /**
     * @param leavesToCorrect      the list of leaves that should be corrected
     * @param indexInPath          the index where we are in the list of leaves
     * @param howToRemediateLeaves a vector of how each leaf can be corrected
     * @return The list of remediation actions : A1 OR A2 OR A3 where A1 = A1.1 AND A1.2 AND A1.3 ...
     */
    static private List<List<RemediationAction>> computeRemediationToPathWithLeafRemediations(List<Vertex> leavesToCorrect, int indexInPath, HashMap<Integer, List<List<RemediationAction>>> howToRemediateLeaves)
    {
    	Logger.getAnonymousLogger().log( Level.INFO, "computeRemediationToPathWithLeafRemediations leavesToCorrect# = " + leavesToCorrect.size() + ", indexInPath = " + indexInPath);

        //Recursive function on the number of remaining leaves to correct
        if (indexInPath > leavesToCorrect.size() - 1)
        { //path empty
            //Normally this case should never happen
        	Logger.getAnonymousLogger().log( Level.INFO, "Anomalous call in computeRemediationToPathWithLeafRemediations()");
            return new ArrayList<List<RemediationAction>>();
        }
        else if (indexInPath == leavesToCorrect.size() - 1)
        { //one leaf
            //Stop case of the recursion, we return the mean to correct only one leaf
            Vertex currentLeaf = leavesToCorrect.get(indexInPath);
            Logger.getAnonymousLogger().log( Level.INFO, "recursion termination in computeRemediationToPathWithLeafRemediations()");
            return howToRemediateLeaves.get(currentLeaf.id);
        }
        else
        { //more than one leaf in path
            Vertex currentLeaf = leavesToCorrect.get(indexInPath);

            //First we correct the other leaves and get the result
            List<List<RemediationAction>> result_remediation_path_without_last_leaf = computeRemediationToPathWithLeafRemediations(leavesToCorrect, indexInPath + 1, howToRemediateLeaves);

            List<List<RemediationAction>> resultWithoutLastLeaf = new ArrayList<List<RemediationAction>>();
            for (List<RemediationAction> aResult_remediation_path_without_last_leaf1 : result_remediation_path_without_last_leaf)
            {
                List<RemediationAction> contentResultToDuplicate = new ArrayList<RemediationAction>(aResult_remediation_path_without_last_leaf1);
                resultWithoutLastLeaf.add(contentResultToDuplicate);
            }

            List<List<RemediationAction>> result_to_duplicate = new ArrayList<List<RemediationAction>>();
            for (List<RemediationAction> aResult_remediation_path_without_last_leaf : result_remediation_path_without_last_leaf)
            {
                List<RemediationAction> contentResultToDuplicate = new ArrayList<RemediationAction>(aResult_remediation_path_without_last_leaf);
                result_to_duplicate.add(contentResultToDuplicate);
            }


            List<List<RemediationAction>> result = new ArrayList<List<RemediationAction>>();

            //Then, we add each element of remediation concerning the current leaf:
            List<List<RemediationAction>> howToRemediateLeaf = howToRemediateLeaves.get(currentLeaf.id);

            //FOR ALL OR CONDITIONS (remediations of the current leaf)
            //we duplicate the old result (result_remediation_path_without_last_leaf) howToRemediateLeaf.size() - 1 times
            //and add all the howToRemediateLeaf.get(i) to each duplicates

            //For the first OR, no duplicate is useful
            //Add the howToRemediateLeaf.get(i) to all OR elements
            for (List<RemediationAction> aResultWithoutLastLeaf : resultWithoutLastLeaf)
            {
                aResultWithoutLastLeaf.addAll(new ArrayList<RemediationAction>(howToRemediateLeaf.get(0)));
            }
            result.addAll(resultWithoutLastLeaf);

            //For the other OR, we can duplicate
            for (int i = 1; i < howToRemediateLeaf.size(); i++)
            {
                //Create the duplicate and add the howToRemediateLeaf.get(i) results into it
                List<List<RemediationAction>> duplicate = new ArrayList<List<RemediationAction>>();
                for (List<RemediationAction> aResult_to_duplicate : result_to_duplicate)
                {
                    List<RemediationAction> duplicateContent = new ArrayList<RemediationAction>(aResult_to_duplicate);
                    duplicate.add(duplicateContent);
                }

                //For all OR of the duplicate, add the howToRemediateLeaf.get(i)
                for (List<RemediationAction> aDuplicate : duplicate)
                {
                    aDuplicate.addAll(new ArrayList<RemediationAction>(howToRemediateLeaf.get(i)));
                }
                result.addAll(duplicate);
            }

            return result;
        }
    }

    /**
     * Compute all possible combination of k integers < to n
     *
     * @param k integer < n
     * @param n integer
     * @return the list of list of k integers
     */
    public static List<List<Integer>> combination(int k, int n) {

        Logger.getAnonymousLogger().log( Level.INFO, "computing C(" + k + "," + n + ")" );

        List<Integer> listNumber = new ArrayList<Integer>();
        for (int i = 0; i < n; i++) {
            listNumber.add(i);
        }

        List<List<Integer>> result = new ArrayList<List<Integer>>();
        combinationRecursive(k, listNumber, 0, new ArrayList<Integer>(), result);
        return result;
    }

    /**
     * Main recursive function used to calculate the combination list combination(k,n)
     */
    private static void combinationRecursive(int k, List<Integer> listNumber, int startListNumber, List<Integer> temporaryResult, List<List<Integer>> result) {
        if (k == 0) {
            result.add(new ArrayList<Integer>(temporaryResult));
            temporaryResult.clear();
            return;
        }
        if (listNumber.size() == startListNumber) return;

        List<Integer> temporaryResult2 = new ArrayList<Integer>(temporaryResult);
        temporaryResult.add(listNumber.get(startListNumber));
        combinationRecursive(k - 1, listNumber, startListNumber + 1, temporaryResult, result);
        combinationRecursive(k, listNumber, startListNumber + 1, temporaryResult2, result);
    }

    /**
     * Get all the machines that are involved in this attack path considered only as a list of vertices
     *
     * @param topology   the Network topology
     * @param attackPath the attack path to explore
     * @return the list of machine involved in this attack path
     * @throws Exception
     */
    public static List<InformationSystemHost> getInvolvedMachines(InformationSystem topology, List<Vertex> attackPath) throws Exception {
        List<InformationSystemHost> result = new ArrayList<InformationSystemHost>();
        for (Vertex vertex : attackPath) {
            if (vertex.fact != null && vertex.fact.type != FactType.RULE) {
                InformationSystemHost machine = vertex.getRelatedMachine(topology);
                result.add(machine);
            }
        }
        return result;
    }

    public static List<AttackPath> loadAttackPathsFromFile(String attackPathsFilePath, AttackGraph relatedAttackGraph) throws Exception {
        FileInputStream file = new FileInputStream(attackPathsFilePath);
        SAXBuilder sxb = new SAXBuilder();
        Document document = sxb.build(file);
        Element root = document.getRootElement();

        List<AttackPath> result = new ArrayList<AttackPath>();

        List<Element> attackPathsElements = root.getChildren("attack_path");
        if (!attackPathsElements.isEmpty())
        {
        	int attack_path_id = 0;
            for (Element attackPathElement : attackPathsElements)
            {
                if (attackPathElement != null)
                {
                    AttackPath attackPath = new AttackPath();
                    attackPath.id = attack_path_id++;
                    attackPath.loadFromDomElementAndAttackGraph(attackPathElement, relatedAttackGraph);
                    result.add(attackPath);
                }
            }
        }
        sortAttackPaths(result);

        return result;

    }

    /**
     * Sort attack paths with their scoring in descending order
     */
    public static void sortAttackPaths(List<AttackPath> attackPathList) {
        Collections.sort(attackPathList, new AttackPath.AttackPathComparator());
    }

    /**
     * @return the leaves of the attack graph
     */
    public List<Vertex> getLeavesThatCanBeRemediated()
    {
	Logger.getAnonymousLogger().log(Level.INFO, "getLeavesThatCanBeRemediated()" );

        List<Vertex> result = new ArrayList<Vertex>();
        for (int i : this.vertices.keySet())
        {
            Vertex vertex = this.vertices.get(i);

	    Logger.getAnonymousLogger().log(Level.INFO, "looking vertex " + vertex.toLongString() );

            vertex.computeParentsAndChildren(this);

            if (vertex.parents.size() == 0)
            {
	    	Logger.getAnonymousLogger().log(Level.INFO, "vertex without parents" );

                if (vertex.fact != null && vertex.fact.datalogCommand != null && vertex.fact.datalogCommand.command != null)
                {
                    String command = vertex.fact.datalogCommand.command;
                    if (command.equals("vulExists") || command.equals("hacl") || command.equals("haclprimit") || command.toLowerCase().contains("vlan") || command.equals("attackerLocated") || command.equals("vmOnHost") || command.equals("vmInDomain") || command.equals("ndnServiceInfo") )
		    {
	    		Logger.getAnonymousLogger().log(Level.INFO, "vertex can be remediated" );
                        result.add(vertex);
		    }

                }
            } else /* vertex.parents.size() > 0 */ {

	    	Logger.getAnonymousLogger().log(Level.INFO, "vertex with parents" );

                if (vertex.fact != null && vertex.fact.datalogCommand != null && vertex.fact.datalogCommand.command != null && vertex.fact.datalogCommand.command.equals("hacl"))
                {
	    	    Logger.getAnonymousLogger().log(Level.INFO, "vertex can be remediated" );
                    result.add(vertex);
                }
            }
        }
        return result;
    }

    /**
     * @return the goal of the attack graph
     */
    public Vertex getGoal() {
        if (goal == null) {
            for (int i : this.vertices.keySet()) {
                Vertex vertex = this.vertices.get(i);
                vertex.computeParentsAndChildren(this);
                if (vertex.children.size() == 0)
                    goal = vertex;
            }
        }
        return goal;
    }

    /**
     * Test if the vertices list contains at least one set in lists.
     * @param vertices : a set of vertices
     * @param lists : a list of sets (lists) of vertices
     * @return true iif vertices is a superset of at least one list of 'lists'
     */
    boolean isSuperSubSet(List<Vertex> vertices, List<List<Vertex>> lists)
    {
    	for (List<Vertex> l : lists)
    	{
    		boolean result = true;
    		for (Vertex v : l)
    		{
    			if (!vertices.contains(v)) result = false;
    		}
    		if  (result) return true;
    	}
    	return false;
    }
    
    /**
     * Print the Datalog command facts of some vertices
     * @param vertices
     */
    void printVertices(List<Vertex> vertices)
    {
    	Logger.getAnonymousLogger().log( Level.INFO, "Leaves sufficient subset : ");
    	for (Vertex v : vertices)
    	{
    		if  (v.fact != null && v.fact.datalogCommand != null && v.fact.datalogCommand.command != null)
    		{
    			Logger.getAnonymousLogger().log( Level.INFO, v.fact.datalogCommand.command + "(");
    			for (int i = 0 ; i < v.fact.datalogCommand.params.length ; i++) {
				Logger.getAnonymousLogger().log( Level.INFO, v.fact.datalogCommand.params[i] + ',');
			}
    			Logger.getAnonymousLogger().log( Level.INFO, ") + ");
    		}
    	}
    	//Logger.getAnonymousLogger().log( Level.INFO, "\n");
    }

    /**
     * @param topology the network topology
     * @param conn     database connection
     * @return the list of possible remediation actions to remediate this attack path : remediation[1] OR remediation[2] OR remediation[3] ; remediation[1] = remediation[1][1] AND remediation[1][2]... [Withour snort rules]
     */
    protected List<List<RemediationAction>> getRemediationActions(InformationSystem topology, Connection conn, String costParametersFolder) throws Exception {

        Logger.getAnonymousLogger().log( Level.INFO, "getRemediationActions()");

        List<List<RemediationAction>> result = new ArrayList<List<RemediationAction>>();
        boolean useSnortRules = true;
        
        double startTime   = System.nanoTime();

        List<Vertex> leavesThatCanBeRemediated = this.getLeavesThatCanBeRemediated();

        double endTime     = System.nanoTime();
        double processTime = (endTime - startTime) / 1000000;
        Logger.getAnonymousLogger().log( Level.INFO, "getLeavesThatCanBeRemediated time : " + processTime + " ms");

        startTime = endTime;

        int cpt_enumeration = 0;

        // compute all possible sufficient combination of leaves to cut the attack path
        List<List<Vertex>> sufficientLeavesToCutPath = new ArrayList<List<Vertex>>();
        List<Vertex> remainingLeaves = new ArrayList<Vertex>(leavesThatCanBeRemediated);

        for( int simultaneousLeavesNumber = 1; simultaneousLeavesNumber <= remainingLeaves.size(); simultaneousLeavesNumber++ )
        { 
	    // while we take a number of leaves lower than the number of remaining leaves
            List<List<Integer>> combination = combination(simultaneousLeavesNumber, remainingLeaves.size());
            List<Vertex> leavesSufficient = new ArrayList<Vertex>();

            //TODO : improve this function : can be much faster.
            for (List<Integer> aCombination : combination)
            {
            	cpt_enumeration++;
                List<Vertex> leavesToTest = new ArrayList<Vertex>();

                for (Integer anACombination : aCombination)
                {
                    leavesToTest.add(remainingLeaves.get(anACombination).clone());
                }
                if (isSuperSubSet(leavesToTest, sufficientLeavesToCutPath) || leavesToTest.size() == 0) 
		{
			continue;  // if the leaves contains another leaves set that is sufficient to cut attack
		}
                if (leavesMandatoryForGoal(leavesToTest))
                {
                	// remove leaves that cannot be remediated but must be present on the graph

                	List<Vertex> leavesToTest2 = new ArrayList<Vertex>();

                	for (Vertex v : leavesToTest)
                	{
                		if ( v.isRemediable() ) 
                		{
                			leavesToTest2.add(v);
                		}
                	}
                	leavesToTest = leavesToTest2;
                	sufficientLeavesToCutPath.add(leavesToTest);
                	leavesSufficient.addAll(leavesToTest);
                	printVertices(leavesToTest);
                }
            }

            /*for (Vertex aLeavesSufficient : leavesSufficient)
            {
                remainingLeaves.remove(aLeavesSufficient);
            }*/
        }
        
        Logger.getAnonymousLogger().log( Level.INFO, "number of sufficient leaves subsets found : " + sufficientLeavesToCutPath.size());
        
        endTime     = System.nanoTime();
        processTime = (endTime - startTime) / 1000000;
        Logger.getAnonymousLogger().log( Level.INFO, "combinatorial enumeration time : " + processTime + " ms (" + cpt_enumeration + " leaves subsets)");

	if( sufficientLeavesToCutPath.isEmpty() ) {

		Logger.getAnonymousLogger().log( Level.INFO, "Can not cut path !!!");

	} else {

		startTime = endTime;

		// Create a hashlist of the list of remediation for each leaf 
		// (possible_actions[1] OR possible_actions[2] OR possible_actions[3] .... 
		// with possible_actions[1] = possible_actions[1][1] AND possible_actions[1][2] AND possible_actions[1][3]
		HashMap<Integer, List<List<RemediationAction>>> howToRemediateLeaves = new HashMap<Integer, List<List<RemediationAction>>>();

		for (Vertex leafThatCanBeRemediated : leavesThatCanBeRemediated) 
		{
		    howToRemediateLeaves.put( leafThatCanBeRemediated.id, getRemediationActionForLeaf(leafThatCanBeRemediated, topology, conn, costParametersFolder, useSnortRules));
		}
		
		endTime     = System.nanoTime();
		processTime = (endTime - startTime) / 1000000;
		Logger.getAnonymousLogger().log( Level.INFO, "remediation per leaf computation time : " + processTime + " ms");
		startTime   = endTime;

		//Try to see how to remediate each list of leaf
		for (List<Vertex> aSufficientLeavesToCutPath : sufficientLeavesToCutPath)
		{
		    //List<RemediationAction> pathRemediations = new ArrayList<RemediationAction>();
		    boolean pathCanBeRemediated = true;

		    //For all leaf list that can cut the attack path
		    for (Vertex leaf : aSufficientLeavesToCutPath)
		    {
			if (howToRemediateLeaves.get(leaf.id).isEmpty()) pathCanBeRemediated = false;
		    }
		    if (pathCanBeRemediated)
		    {
			result.addAll(computeRemediationToPathWithLeafRemediations(aSufficientLeavesToCutPath, 0, howToRemediateLeaves));
		    }
		}
		
		endTime     = System.nanoTime();
		processTime = (endTime - startTime) / 1000000;
		Logger.getAnonymousLogger().log( Level.INFO, "remediation proposition fusion time : " + processTime + " ms");
	}

        return result;
    }

    /**
     * @param topology             the network topology
     * @param conn                 the database connection
     * @param costParametersFolder the folder where the cost parameters are stored
     * @return the list of deployable remediations without snort rules
     * @throws Exception
     */
    public List<DeployableRemediation> getDeployableRemediations(InformationSystem topology, Connection conn, String costParametersFolder) throws Exception
    {
        Logger.getAnonymousLogger().log( Level.INFO, "getDeployableRemediations()");

        List<List<RemediationAction>> remediationActionListOfList = getRemediationActions(topology, conn, costParametersFolder);
        List<DeployableRemediation>   result                      = new ArrayList<DeployableRemediation>();
        
        double startTime = System.nanoTime();
        
        Logger.getAnonymousLogger().log( Level.INFO, "remediationActionListOfList nb=" + remediationActionListOfList.size() );

        //For all "OR" remediations
        for (List<RemediationAction> remediationActionList : remediationActionListOfList)
        {
            List<DeployableRemediation> result_tmp = new ArrayList<DeployableRemediation>(); //Result for only this group of remediations

            DeployableRemediation dr = new DeployableRemediation(this, topology);
            dr.setActions(new ArrayList<DeployableRemediationAction>());
            result_tmp.add(dr);

            //For all "AND" remediations
            for (RemediationAction remediationAction : remediationActionList)
            {
                if (remediationAction.getPossibleMachines().size() > 1)
                {
                    //ALL MACHINES EXCEPT THE FIRST ONE
                    List<DeployableRemediation> resultForThisRemediationAction = new ArrayList<DeployableRemediation>(); //Result for only this group of remediations
                    for (int m = 1; m < remediationAction.getPossibleMachines().size(); m++)
                    {
                        //For all the previously added Deployable Remediation Actions
                        for (DeployableRemediation aResult_tmp : result_tmp)
                        {
                            DeployableRemediation newdr = new DeployableRemediation(this, topology);
                            resultForThisRemediationAction.add(newdr);
                            newdr.getActions().addAll(aResult_tmp.getActions());
                            DeployableRemediationAction deployableRemediationAction = new DeployableRemediationAction();
                            deployableRemediationAction.setRemediationAction(remediationAction);
                            deployableRemediationAction.setHost(remediationAction.getPossibleMachines().get(m));

			    Logger.getAnonymousLogger().log( Level.INFO, "adding tmp deployableRemediationAction " + deployableRemediationAction);
                            newdr.getActions().add(deployableRemediationAction);
                        }
                    }
                    //FIRST MACHINE
                    for (DeployableRemediation aResult_tmp : result_tmp)
                    { //For all the previously added Deployable Remediation Actions
                        DeployableRemediationAction deployableRemediationAction = new DeployableRemediationAction();
                        deployableRemediationAction.setRemediationAction(remediationAction);
                        deployableRemediationAction.setHost(remediationAction.getPossibleMachines().get(0));

		        Logger.getAnonymousLogger().log( Level.INFO, "adding tmp deployableRemediationAction" + deployableRemediationAction );
                        aResult_tmp.getActions().add(deployableRemediationAction);
                    }
                    result_tmp.addAll(resultForThisRemediationAction);
                }
                else if (remediationAction.getPossibleMachines().size() == 1)
                {
                    for (DeployableRemediation aResult_tmp : result_tmp)
                    {
                        DeployableRemediationAction deployableRemediationAction = new DeployableRemediationAction();
                        deployableRemediationAction.setRemediationAction(remediationAction);
                        deployableRemediationAction.setHost(remediationAction.getPossibleMachines().get(0));

		        Logger.getAnonymousLogger().log( Level.INFO, "adding tmp deployableRemediationAction" + deployableRemediationAction );
                        aResult_tmp.getActions().add(deployableRemediationAction);
                    }
                }
            }

            //Add all the non empty Deployable Remediation Action to the result
            for (DeployableRemediation aResult_tmp : result_tmp)
            {
                if (aResult_tmp.getActions().size() > 0) {
		        Logger.getAnonymousLogger().log( Level.INFO, "adding deployableRemediation" );
			result.add(aResult_tmp);
		} else {
		        Logger.getAnonymousLogger().log( Level.INFO, "ignoring empty deployableRemediation" );
		}
            }
        }

        //Compute the cost of all remediation action
        for (DeployableRemediation aResult : result) {
            aResult.computeCost();
        }

        double endTime = System.nanoTime();
        double processTime = (endTime - startTime) / 1000000;
        Logger.getAnonymousLogger().log( Level.INFO, "Deployable computation time : " + processTime + " ms");
        startTime = endTime;
        
        Collections.sort(result, new DeployableRemediationComparator());
        endTime = System.nanoTime();
        processTime = (endTime - startTime) / 1000000;
        Logger.getAnonymousLogger().log( Level.INFO, "Deployable remediation sorting time : " + processTime + " ms");

        return result;
    }

    /**
     * This function compute the scoring of this attack path (float between 0 and 1 : 1 = will arrive ; 0 = can't arrive
     */
    public void computeScoring() {
        scoring = 1.;
        for (int i : this.vertices.keySet()) {
            Vertex vertex = this.vertices.get(i);
            if (vertex.fact != null && vertex.fact.type == FactType.DATALOG_FACT) {
                DatalogCommand command = vertex.fact.datalogCommand;
                if (command.command.equals("vulExists")) {
                    scoring *= 1. / 2;
                }
                if (command.command.equals("cvss") && command.params[1].equals("l")) {
                    scoring *= 1. / 5;
                }
                if (command.command.equals("cvss") && command.params[1].equals("m")) {
                    scoring *= 1. / 10;
                }
                if (command.command.equals("cvss") && command.params[1].equals("h")) {
                    scoring *= 1. / 20;
                } else if (command.command.equals("inCompetent")) {
                    scoring *= 1. / 100;
                }
            }
        }
    }

    /**
     * Print the list of remediations that could be applied to prevent the attack
     *
     * @param topology the network topology
     * @param conn     the database connection
     * @throws Exception
     */
    // UNUSED !!!
    protected void printListRemediations(InformationSystem topology, Connection conn) throws Exception {
        List<Vertex> leaves = this.getLeavesThatCanBeRemediated();
        if (this.getGoal() != null) {
            Logger.getAnonymousLogger().log( Level.INFO, "The goal of this attack is vertex " + this.getGoal().id);
            if (this.getGoal().fact != null && this.getGoal().fact.factString != null)
                Logger.getAnonymousLogger().log( Level.INFO, " : " + this.getGoal().fact.factString);
            //System.out.println();
        }
        Logger.getAnonymousLogger().log( Level.INFO, "The attack path contains " + leaves.size() + " leaves : ");

        List<List<Vertex>> sufficientLeavesToCutPath = new ArrayList<List<Vertex>>();
        List<Vertex> remainingLeaves = new ArrayList<Vertex>(leaves);
        int simultaneousLeavesNumber = 1;

        while (simultaneousLeavesNumber <= remainingLeaves.size()) { //While we take a number of leaves lower than the number of remaining leaves
            List<List<Integer>> combination = combination(simultaneousLeavesNumber, remainingLeaves.size());
            List<Vertex> leavesSufficient = new ArrayList<Vertex>();

            for (List<Integer> aCombination : combination) {
                List<Vertex> leavesToTest = new ArrayList<Vertex>();
                for (Integer anACombination : aCombination) {
                    leavesToTest.add(remainingLeaves.get(anACombination));
                }
                if (leavesMandatoryForGoal(leavesToTest)) {
                    sufficientLeavesToCutPath.add(leavesToTest);
                    leavesSufficient.addAll(leavesToTest);
                }
            }

            for (Vertex aLeavesSufficient : leavesSufficient) {
                remainingLeaves.remove(aLeavesSufficient);
            }

            simultaneousLeavesNumber++;
        }

        Logger.getAnonymousLogger().log( Level.INFO, "Here are the list of all the combinations of leaves that permit to cut the attack path ");
        for (int i = 0; i < sufficientLeavesToCutPath.size(); i++) {
            Logger.getAnonymousLogger().log( Level.INFO, "Combination  " + (i + 1) + " : ");
            for (int j = 0; j < sufficientLeavesToCutPath.get(i).size(); j++) {
                Logger.getAnonymousLogger().log( Level.INFO, "Leaf " + sufficientLeavesToCutPath.get(i).get(j).id);
                if (j < sufficientLeavesToCutPath.get(i).size() - 1)
                    Logger.getAnonymousLogger().log( Level.INFO, " + ");
            }
            //System.out.println();
        }

        Logger.getAnonymousLogger().log( Level.INFO, "\n------------------------------------");
        Logger.getAnonymousLogger().log( Level.INFO, "Here is how to remediate each leaf :");
        Logger.getAnonymousLogger().log( Level.INFO, "------------------------------------");

        for (Vertex leaf : leaves) {
            Logger.getAnonymousLogger().log( Level.INFO, remediateLeaf(leaf, topology, conn));
            Logger.getAnonymousLogger().log( Level.INFO, "----------------------------------");
        }

    }

    /**
     * @param leaf     An attack path leaf
     * @param topology the network topology
     * @param conn     the database connection
     * @return The string that contains the text to remediate a leaf
     * @throws Exception
     */
    // UNUSED !!!
    protected String remediateLeaf(Vertex leaf, InformationSystem topology, Connection conn) throws Exception {
        String result = "";
        result += "* Leaf " + leaf.id + "\n";
        if (leaf.fact != null && leaf.fact.type == FactType.DATALOG_FACT && leaf.fact.datalogCommand != null) {
            DatalogCommand command = leaf.fact.datalogCommand;
            result += "Datalog fact : " + command.command + "\n";

            switch (command.command) {
                case "vulExists": {
                    Vulnerability vuln = new Vulnerability(conn, Vulnerability.getIdVulnerabilityFromCVE(command.params[1], conn));
                    List<List<InformationSystemHost>> attackerPath = getAttackerRouteToAVulnerability(leaf, topology);
                    result += "To exploit the vulnerability " + vuln.cve + " the packets of the attacker will pass the following machines : " + "\n";
                    for (int j = 0; j < attackerPath.size(); j++) {
                        if (attackerPath.size() > 1)
                            result += "Path " + (j + 1) + " : " + "\n";
                        result += "- ";
                        for (int k = 0; k < attackerPath.get(j).size(); k++) {
                            result += attackerPath.get(j).get(k).getName();
                            if (k < attackerPath.get(j).size() - 1)
                                result += " -> ";
                        }
                        result += "\n";
                        List<Patch> patches = vuln.getPatchs(conn);
                        List<Rule> rules = vuln.getRules(conn);
                        if (patches.size() > 0) {
                            result += "To protect against this vulnerability, the following patch(es) can be applied on machine \"" + leaf.getRelatedMachine(topology).getName() + "\" : " + "\n";
                            for (int m = 0; m < patches.size(); m++) {
                                result += patches.get(m).getLink();
                                if (m < patches.size() - 1)
                                    result += " ; ";
                            }
                            result += "\n";
                        }
                        if (rules.size() > 0) {
                            result += "To protect against this vulnerability, the following rule(s) can be used on at least one machine of the attacker path : " + "\n";
                            for (Rule rule : rules) {
                                result += "-" + rule.getRule() + "\n";
                            }
                        }
                    }
                    break;
                }
                case "inCompetent":
                    result += "To protect against this attack, the user \"" + command.params[0] + "\" should be trained " + "\n";
                    break;
                case "attackerLocated":
                    result += "To protect against this attack, people should know that the attacker is located on \"" + command.params[0] + "\" \n";
                    break;
                case "hasAccount":
                    result += "To protect against this attack, the account \"" + command.params[2] + "\" on the machine \"" + leaf.getRelatedMachine(topology).getName() + "\" should be closed\n";
                    break;
                case "hacl": {
                    InformationSystemHost from = topology.getHostByNameOrIPAddress(command.params[0]);
                    InformationSystemHost to = topology.getHostByNameOrIPAddress(command.params[1]);
                    List<List<InformationSystemHost>> attackerPath = command.getRoutesBetweenHostsOfHacl(topology);
                    result += "The attacker packets will use one of the following paths : \n";
                    for (int j = 0; j < attackerPath.size(); j++) {
                        if (attackerPath.size() > 1)
                            result += "Path " + (j + 1) + " : " + "\n";
                        result += "- ";
                        for (int k = 0; k < attackerPath.get(j).size(); k++) {
                            result += attackerPath.get(j).get(k).getName();
                            if (k < attackerPath.get(j).size() - 1)
                                result += " -> ";
                        }
                        result += "\n";
                    }
                    Logger.getAnonymousLogger().log( Level.INFO, "The following firewall rule should be deployed on all the paths between \"" + from.getName() + "\" and \"" + to.getName() + "\". (See above)");
                    if (command.params[0].equals("internet")) {
                        result += "DROP\t" + Protocol.getProtocolFromString(command.params[2]) + "\t--\t0.0.0.0/0\t" + to.getFirstIPAddress().getAddress() + "/32\t" + "dpt:" + Service.portStringToInt(command.params[3]) + "\n";
                    } else if (command.params[1].equals("internet")) {
                        result += "DROP\t" + Protocol.getProtocolFromString(command.params[2]) + "\t--\t" + from.getFirstIPAddress().getAddress() + "/32\t0.0.0.0/0\t" + "dpt:" + Service.portStringToInt(command.params[3]) + "\n";
                    } else {
                        result += "DROP\t" + Protocol.getProtocolFromString(command.params[2]) + "\t--\t" + from.getFirstIPAddress().getAddress() + "/32\t" + to.getFirstIPAddress().getAddress() + "/32\t" + "dpt:" + Service.portStringToInt(command.params[3]) + "\n";
                    }
                    break;
                }
            }
        } else {
            throw new Exception("Leaf is not a datalog fact");
        }
        if (leafMandatoryForGoal(leaf))
            result += "If this can be corrected, this attack path will be broken" + "\n";
        else
            result += "Deleting only this vulnerability is not sufficient to cut the attack path" + "\n";
        return result;
    }

    /**
     * @param leaf         An attack path leaf
     * @param topology     the network topology
     * @param conn         the database connection
     * @param useSnortRule : if true, use the snort rules else don't use it for remediation
     * @return the possible remediation action to remediate this leaf. To remediate the leaf, we can apply remediation[1] OR remediation[2] OR remediation[3]
     * the remediation[1] is remediation[1][1] AND remediation[1][2] AND remediation[1][3] etc...
     * @throws Exception
     */
    protected List<List<RemediationAction>> getRemediationActionForLeaf(Vertex leaf, InformationSystem topology, Connection conn, String costParametersFolder, boolean useSnortRule) throws Exception {

	Logger.getAnonymousLogger().log(Level.INFO, "getRemediationActionForLeaf(" + leaf.toLongString() + ")" );

        List<List<RemediationAction>> result = new ArrayList<List<RemediationAction>>();

        if (leaf.fact != null && leaf.fact.type == FactType.DATALOG_FACT && leaf.fact.datalogCommand != null) {

            DatalogCommand command = leaf.fact.datalogCommand;

            switch (command.command) {

                case "vulExists": {

                    boolean use_magic = false;

                    if( use_magic ) {
			    RemediationAction magic = new MagicRemediationAction();
			    magic.setRelatedVertex(leaf);
			    // magic.getPossibleMachines().add(leaf.getRelatedMachine(topology));
			    List<RemediationAction> magicRemediateVulnerability = new ArrayList<RemediationAction>();
			    magicRemediateVulnerability.add( magic );
			    Logger.getAnonymousLogger().log(Level.INFO, "adding action: " + magicRemediateVulnerability );
			    result.add( magicRemediateVulnerability );
                    }

                    List<RemediationAction> remediateVulnerability = new ArrayList<RemediationAction>();

		    int vulnId = Vulnerability.getIdVulnerabilityFromCVE(command.params[1], conn);

		    if( -1 == vulnId ) {

			    Logger.getAnonymousLogger().log(Level.INFO, "Vulnerability not found in database" );

                    } else {

			    Logger.getAnonymousLogger().log(Level.INFO, "Vulnerability found in database id=" + vulnId );

			    Vulnerability vulnerability = new Vulnerability(conn, vulnId);
			    Logger.getAnonymousLogger().log(Level.INFO, "Handling vulExists: " + vulnerability );

			    List<List<InformationSystemHost>> attackerPath = getAttackerRouteToAVulnerability(leaf, topology);

			    List<Patch> patches = vulnerability.getPatchs(conn); //Get the path of this vulnerability

			    Logger.getAnonymousLogger().log(Level.INFO, "vuln has patch nb = " + patches.size() );

			    if (patches.size() == 0) {

				if( command.params.length >= 2 ) {
					String productName = command.params[2];
					Patch upgradePatch = Patch.upgradeToLastKnownVersion(conn, productName);

					if( null != upgradePatch ) {
						Logger.getAnonymousLogger().log(Level.INFO, "add " + productName + " upgrade patch");
						patches.add( upgradePatch );
					}
				}
			    }

			    if (patches.size() > 0) {

				PatchRemediationAction remediation = new PatchRemediationAction(costParametersFolder);
				remediation.setRelatedVertex(leaf);
				remediation.getPossibleMachines().add(leaf.getRelatedMachine(topology));

				for (Patch patche : patches) {
				    remediation.patches.add(patche);
				}
				remediateVulnerability.add(remediation);
				Logger.getAnonymousLogger().log(Level.INFO, "adding action: " + remediateVulnerability );
				result.add(remediateVulnerability);
			    }

			    List<Rule> rules = vulnerability.getRules(conn); //Get the snort rules related to this vulnerability

			    if (rules.size() > 0 && useSnortRule) {
				//If there is a rule, to remediate the leaf, we can deploy rule 1 OR rule 2 OR rule 3 but on ALL possible paths
				List<RemediationAction> detectVulnerabilityOnAllPath = new ArrayList<RemediationAction>();
				//For all possible path
				for (List<InformationSystemHost> anAttackerPath : attackerPath) {

				    SnortRemediationAction remediation = new SnortRemediationAction(costParametersFolder);
				    remediation.setRelatedVertex(leaf);
				    for (Rule rule : rules) {
					rule.setRule(rule.getRule().replaceFirst("alert", "reject"));
					remediation.rules.add(rule);
				    }

				    for (InformationSystemHost anAnAttackerPath : anAttackerPath) {
					//TODO : Add the machine to the "possible machines" only if snort is installed  (need a way to specify this in the input file)
					//if(attackerPath.get(j).get(incr).getServices().containsKey("snort"))
					remediation.getPossibleMachines().add(anAnAttackerPath); //The path
				    }

				    detectVulnerabilityOnAllPath.add(remediation);
				}
				//Add the detection of vulnerability on all path
				result.add(detectVulnerabilityOnAllPath);
			    }
		    }
                    break;
                }
                case "inCompetent": {

                    List<RemediationAction> trainUser = new ArrayList<RemediationAction>();

                    TrainUserRemediationAction remediation = new TrainUserRemediationAction( command.params[0], costParametersFolder );
                    remediation.setRelatedVertex(leaf);

                    trainUser.add(remediation);
                    result.add(trainUser);
                    break;
                }
                case "hacl":
                case "haclprimit": {

                    InformationSystemHost from = topology.getHostByNameOrIPAddress(command.params[0]);
                    InformationSystemHost to   = topology.getHostByNameOrIPAddress(command.params[1]);
                    List<List<InformationSystemHost>> attackerPath = command.getRoutesBetweenHostsOfHacl(topology);

                    //For HACL Rules, we can block the packets with firewall rules
                    //These rules can be deployed either on the input firewall table or on the output firewall table
                    //It depends of the machines
                    //TODO : things needs to be corrected, to add remediations with "alternating" between INPUT and OUTPUT rules
                    //FIRST LET'S DO THE INPUT RULES

                    List<RemediationAction> blockAttackerOnAllPath = new ArrayList<RemediationAction>();
                    //For all possible path
                    for (List<InformationSystemHost> anAttackerPath1 : attackerPath) {

                        FirewallRemediationAction remediation = new FirewallRemediationAction(costParametersFolder);
                        remediation.setRelatedVertex(leaf);
                        if (command.params[0].equals("internet")) {
                            FirewallRule fwRule = new FirewallRule(Action.DROP, Protocol.getProtocolFromString(command.params[2]), new IPAddress("0.0.0.0"), new IPAddress("0.0.0.0"), new PortRange(true), to.getFirstIPAddress(), new IPAddress("255.255.255.255"), PortRange.fromString(command.params[3]), Table.INPUT);
                            remediation.rule = fwRule;
                        } else if (command.params[1].equals("internet")) {
                            FirewallRule fwRule = new FirewallRule(Action.DROP, Protocol.getProtocolFromString(command.params[2]), from.getFirstIPAddress(), new IPAddress("255.255.255.255"), new PortRange(true), new IPAddress("0.0.0.0"), new IPAddress("0.0.0.0"), PortRange.fromString(command.params[3]), Table.INPUT);
                            remediation.rule = fwRule;
                        } else {
                            FirewallRule fwRule = new FirewallRule(Action.DROP, Protocol.getProtocolFromString(command.params[2]), from.getFirstIPAddress(), new IPAddress("255.255.255.255"), new PortRange(true), to.getFirstIPAddress(), new IPAddress("255.255.255.255"), PortRange.fromString(command.params[3]), Table.INPUT);
                            remediation.rule = fwRule;
                        }
                        //The only thing that change between INPUT and OUTPUT is the machines on which this rule can be deployed
                        for (InformationSystemHost currentAttackerPathHost : anAttackerPath1) {
                            if (command.params[0].equals("internet")) {//Source packet is internet, input will block on all hosts
                                remediation.getPossibleMachines().add(currentAttackerPathHost);
                            } else {
                                InformationSystemHost sourceHost = topology.existingMachineByNameOrIPAddress(command.params[0]);
                                if (sourceHost == null || !sourceHost.equals(currentAttackerPathHost)) {//we add this machine to the possible machines if it is not the sender of the packets
                                    remediation.getPossibleMachines().add(currentAttackerPathHost);
                                }
                            }
                        }

                        blockAttackerOnAllPath.add(remediation);
                    }
                    //Add the block of the attacker on all path
                    result.add(blockAttackerOnAllPath);


                    //THEN LET'S DO THE OUTPUT RULES
                    blockAttackerOnAllPath = new ArrayList<RemediationAction>();
                    //For all possible path
                    for (List<InformationSystemHost> anAttackerPath : attackerPath) {

                        FirewallRemediationAction remediation = new FirewallRemediationAction(costParametersFolder);
                        remediation.setRelatedVertex(leaf);
                        if (command.params[0].equals("internet")) {
                            FirewallRule fwRule = new FirewallRule(Action.DROP, Protocol.getProtocolFromString(command.params[2]), new IPAddress("0.0.0.0"), new IPAddress("0.0.0.0"), new PortRange(true), to.getFirstIPAddress(), new IPAddress("255.255.255.255"), PortRange.fromString(command.params[3]), Table.OUTPUT);
                            remediation.rule = fwRule;
                        } else if (command.params[1].equals("internet")) {
                            FirewallRule fwRule = new FirewallRule(Action.DROP, Protocol.getProtocolFromString(command.params[2]), from.getFirstIPAddress(), new IPAddress("255.255.255.255"), new PortRange(true), new IPAddress("0.0.0.0"), new IPAddress("0.0.0.0"), PortRange.fromString(command.params[3]), Table.OUTPUT);
                            remediation.rule = fwRule;
                        } else {
                            FirewallRule fwRule = new FirewallRule(Action.DROP, Protocol.getProtocolFromString(command.params[2]), from.getFirstIPAddress(), new IPAddress("255.255.255.255"), new PortRange(true), to.getFirstIPAddress(), new IPAddress("255.255.255.255"), PortRange.fromString(command.params[3]), Table.OUTPUT);
                            remediation.rule = fwRule;
                        }

                        //The only thing that change between INPUT and OUTPUT is the machines on which this rule can be deployed
                        for (InformationSystemHost currentAttackerPathHost : anAttackerPath) {
                            if (command.params[1].equals("internet")) {//Source packet is internet, input will block on all hosts
                                remediation.getPossibleMachines().add(currentAttackerPathHost);
                            } else {
                                InformationSystemHost destinationHost = topology.existingMachineByNameOrIPAddress(command.params[1]);
                                if (destinationHost == null || !destinationHost.equals(currentAttackerPathHost)) {//we add this machine to the possible machines if it is not the receiver of the packets
                                    remediation.getPossibleMachines().add(currentAttackerPathHost);
                                }
                            }
                        }

                        blockAttackerOnAllPath.add(remediation);
                    }
                    //Add the block of the attacker on all path
                    result.add(blockAttackerOnAllPath);
                    break;
                }
                case "vmOnHost":
                {
                    List<RemediationAction> moveVM = new ArrayList<RemediationAction>();
                    String vm         = command.params[0];
                    String hypervisor = command.params[1];
                    MoveVmRemediationAction rem = new MoveVmRemediationAction(vm,hypervisor,costParametersFolder);
                    rem.setRelatedVertex(leaf);

                    List<String> forbidden_hosts = new ArrayList<String>();
                    forbidden_hosts.add(rem.hypervisor);  // cannot move the VM to the same hypervisor 
                    rem.setPossibleMachines(this.getNotVulnerableHosts(topology.getTopology(), forbidden_hosts));  // all new possible hypervisors
                    moveVM.add(rem);
                    result.add(moveVM);
                    break;
                }
                	
                case "vmInDomain":
                {
                    List<RemediationAction> moveVM = new ArrayList<RemediationAction>();
                    String vm         = command.params[0];
                    String domain     = command.params[1];
                    MoveVmDomainRemediationAction rem = new MoveVmDomainRemediationAction(vm,domain,costParametersFolder);
                    rem.setRelatedVertex(leaf);

                    moveVM.add(rem);
                    result.add(moveVM);
                    break;
                }
                
                default :
                {
                	Logger.getAnonymousLogger().log( Level.INFO, "Leaf has non-remediable command : " + command.command);
                }
            }
        }

        return result;
    }

    /**
     * Get the attacker route to access a vulnerability according to the information in the attack path
     *
     * @param leaf     the leaf of the vulnerability
     * @param topology the network topology
     * @return the attacker route
     * @throws Exception
     */
    public List<List<InformationSystemHost>> getAttackerRouteToAVulnerability(Vertex leaf, InformationSystem topology) throws Exception
    {
        List<List<InformationSystemHost>> result = new ArrayList<List<InformationSystemHost>>();
        Vertex v = leaf.children.get(0);
        if (v == null)
        {
            throw new Exception("The leaf a no child");
        }
        for (Vertex child : leaf.children)  // a same vulnerability can be present in multiple rules
        {
            Vertex netAccessVertex = this.getParentOfVertexWithFactCommand(child, "netAccess");
            if (netAccessVertex == null)
            {
                netAccessVertex = this.getParentOfVertexWithFactCommand(child, "accessMaliciousInput");
            }
            if (netAccessVertex != null)
            {
                Vertex ruleAccessVertex = netAccessVertex.parents.get(0);
                if (ruleAccessVertex != null)
                {
                    Vertex haclVertex = this.getParentOfVertexWithFactCommand(ruleAccessVertex, "hacl");
                    if (haclVertex != null)
                    {
                        //return haclVertex.fact.datalogCommand.getRoutesBetweenHostsOfHacl(topology);
                    	result.addAll(haclVertex.fact.datalogCommand.getRoutesBetweenHostsOfHacl(topology));
                    }
                    else throw new Exception("No hacl.");
                }
                else
                {
                    throw new Exception("Problem while going up to the hacl for the leaf " + leaf.id);
                }
            }
            else
            {
                //throw new Exception("Problem while going up to the hacl for the leaf " + leaf.id);
            	// there is no network rule between hosts (e.g. the vulnerability is exploitable through hypervisor)
            	//return new ArrayList<List<InformationSystemHost>>();
            }
        }
        return result;
    }
    
    /**
     * Get the hypervisors of the topology that are not vulnerable for this attack path
     * @param topology : the global topology
     * @return
     */
    public List<InformationSystemHost> getNotVulnerableHosts(Topology topology, List<String> forbidden_hosts)
    {
    	List<Host> hypervisors = topology.getHypervisors();
    	Set<Host> vulnerableH = new HashSet<Host>();
    	for (Integer i : this.vertices.keySet())
    	{
    		Vertex vertex = vertices.get(i);
    		Fact fact = vertex.fact;
    		if (fact != null && fact.type == FactType.DATALOG_FACT)
    		{
    			DatalogCommand command = fact.datalogCommand;
    			if (command != null && (command.command.equals("vulExists")))  // looks for vulnerability facts in the graph
    			{
    				for (Host hypervisor : hypervisors)
    				{
    					if  (hypervisor.getName().equals(command.params[0]) && !vulnerableH.contains(hypervisor))  // get related hypervisor
    					{
    						vulnerableH.add(hypervisor);  // the related hypervisor is vulnerable
    					}
    				}
    			}
    		}
    	}
    	
    	List<InformationSystemHost> result = new ArrayList<InformationSystemHost>();
    	for (Host h : hypervisors)  // keep only not vulnerable hypervisors
    	{
    		if  (!vulnerableH.contains(h) && ! forbidden_hosts.contains(h.getName()))
    		{
    			result.add((InformationSystemHost)h);
    		}
    	}
    	
    	return result;
    }

    /**
     * @param leaf an attack path leaf
     * @return true if the leaf is mandatory to reach the goal of the attack Path
     */
    public boolean leafMandatoryForGoal(Vertex leaf) {
        Vertex goal = this.getGoal();
        if (goal != null) {
            List<Vertex> leaf_list = new ArrayList<Vertex>();
            leaf_list.add(leaf);
            return leavesMandatoryForVertex(leaf_list, goal, new ArrayList<Vertex>());
        }
        return false;
    }

    /**
     * @param leaves a list of leaves
     * @return true if (a subset of) the leaves are mandatory to reach the goal.
     * returns true if removing all the leaves makes the goal unreachable. attackerLocated are not taken in the threat model
     */
    public boolean leavesMandatoryForGoal(List<Vertex> leaves) {
        Vertex goal = this.getGoal();
        return goal != null && leavesMandatoryForVertex(leaves, goal, new ArrayList<Vertex>());
    }

    /**
     * Recursive function that test whether or not leaves are mandatory to access a vertex
     *
     * @param leaves the leaves that will be tested
     * @param v      the vertex
     * @return true if the leaves are mandatory / else false
     * @return true if cutting all the leaves is enough to cut attack path to vertex
     */
    private boolean leavesMandatoryForVertex( List<Vertex> leaves, Vertex v, List<Vertex> alreadySeen )
    {
	Logger.getAnonymousLogger().log( Level.INFO, "leavesMandatoryForVertex(" + v + ")" );

	// vertex of type attackerLocated, isInVlan or vulProperty is not remediable
	// so out of the scope of the remediation
	// => any leaves set is OK
	if( ! v.isRemediable() )
	{
		Logger.getAnonymousLogger().log( Level.INFO, "leavesMandatoryForVertex(" + v + ") = true (not remediable)" );
		return true; 
	}

        if (leaves.contains(v))
	{
		Logger.getAnonymousLogger().log( Level.INFO, "leavesMandatoryForVertex(" + v + ") = true (in leaves)" );
		return true;
	}

        if (v.type == VertexType.AND)
        {
            boolean result = false;
            v.computeParentsAndChildren(this);
            alreadySeen.add(v);
            
            for( Vertex parent : v.parents )
            {
                if( !alreadySeen.contains(parent) )
		{
                    result = result || leavesMandatoryForVertex(leaves, parent, alreadySeen);
		}
            }

            alreadySeen.remove(v);
	    Logger.getAnonymousLogger().log( Level.INFO, "leavesMandatoryForVertex(" + v + ") = " + result + " (AND)" );
            return result;
        }

        if (v.type == VertexType.OR)
        {
            boolean result = true;
            v.computeParentsAndChildren(this);
            alreadySeen.add(v);

            for( Vertex parent : v.parents )
            {
                if( !alreadySeen.contains(parent))
		{
                    result = result && leavesMandatoryForVertex(leaves, parent, alreadySeen);
		}
            }

            alreadySeen.remove(v);
	    Logger.getAnonymousLogger().log( Level.INFO, "leavesMandatoryForVertex(" + v + ") = " + result + " (OR)" );
            return result;
        }

        Logger.getAnonymousLogger().log( Level.INFO, "leavesMandatoryForVertex(" + v + ") = false (default )" );
	return false;
    }

    /**
     * Load the attack path from a DOM element of a XML file (the XML file contains only the arcs, the vertices are in the attack graph)
     *
     * @param root        the DOM element
     * @param attackGraph the corresponding attack graph
     */
    public void loadFromDomElementAndAttackGraph(Element root, AttackGraph attackGraph) {
        Element scoringElement = root.getChild("scoring");
        if (scoringElement != null) {
            this.scoring = Double.parseDouble(scoringElement.getText());
        }
        
        Element targetElement = root.getChild("target");
        if (targetElement != null)
        {
        	this.targetString = targetElement.getText();
        }

		/* Add all the arcs */
        Element arcs_element = root.getChild("arcs");
        if (arcs_element != null) {
            List<Element> arcs = arcs_element.getChildren("arc");
            for (Element arc_element : arcs) { //All arcs
                Element src_element = arc_element.getChild("dst"); //MULVAL XML FILES INVERSE DESTINATION AND DESTINATION
                Element dst_element = arc_element.getChild("src"); //MULVAL XML FILES INVERSE DESTINATION AND DESTINATION
                if (src_element != null && dst_element != null) {
                    Vertex destination = getVertexFromAttackGraph((int) Double.parseDouble(dst_element.getText()), attackGraph);
                    Vertex source = getVertexFromAttackGraph((int) Double.parseDouble(src_element.getText()), attackGraph);
                    Arc arc = new Arc(source, destination);
                    this.arcs.add(arc);
                }
            }
        }
    }

    /**
     * @param vertexID    the vertex number
     * @param attackGraph an attack graph
     * @return the existing vertex if it is already in the attack path else add this vertex from the attack graph
     */
    public Vertex getVertexFromAttackGraph(int vertexID, AttackGraph attackGraph) {
        if (this.vertices.containsKey(vertexID))
            return this.vertices.get(vertexID);
        else {
            Vertex result = attackGraph.getExistingOrCreateVertex(vertexID);
            this.vertices.put(vertexID, result);
            return result;
        }
    }

    /**
     * @return the dom element corresponding to this attack path XML file
     */
    public Element toDomXMLElement() {
        Element root = new Element("attack_path");

        Element idElement = new Element("id");
        idElement.setText(""+this.id);
        root.addContent(idElement);
        Element scoringElement = new Element("scoring");
        scoringElement.setText(this.scoring + "");
        root.addContent(scoringElement);
        Element targetElement = new Element("target");
        targetElement.setText(this.targetString);
        root.addContent(targetElement);
        //arcs
        Element arcsElement = new Element("arcs");
        root.addContent(arcsElement);
        for (Arc arc : arcs) {
            Element arcElement = new Element("arc");
            arcsElement.addContent(arcElement);
            Element srcElement = new Element("src");
            srcElement.setText(arc.destination.id + "");
            arcElement.addContent(srcElement);
            Element dstElement = new Element("dst");
            dstElement.setText(arc.source.id + "");
            arcElement.addContent(dstElement);
        }

        return root;
    }

    @Override
    public String toString() {
        String result = "AttackPath : ";
        for (int i : this.vertices.keySet()) {
            result += this.vertices.get(i).id + " - ";
        }
        return result;
    }

    /**
     * @param informationSystem the information system
     * @return The topology Graph associated to this attack path
     * @throws Exception
     */
    public InformationSystemGraph getRelatedTopologyGraph(InformationSystem informationSystem) throws Exception {
        InformationSystemGraph result = super.getRelatedTopologyGraph(informationSystem);

        result.addTarget(this.getGoal().getRelatedMachine(informationSystem));

        return result;
    }

    @Override
    public AttackPath clone() throws CloneNotSupportedException {
        AttackPath copie = (AttackPath) super.clone();

        if (this.goal != null)
            copie.goal = copie.vertices.get(this.goal.id);

        return copie;
    }

    public static class AttackPathComparator implements Comparator<AttackPath> {
        public int compare(AttackPath a1, AttackPath a2) {
            //descending order
            if (a1.scoring == a2.scoring) {
                return 0;
            } else if (a1.scoring < a2.scoring) {
                return 1;
            } else {
                return -1;
            }
        }
    }

    /**
     * Comparator to compare deployable remediation according to their cost
     */
    private class DeployableRemediationComparator implements Comparator<DeployableRemediation> {
        public int compare(DeployableRemediation dr1, DeployableRemediation dr2) {
            if (dr1.getCost() == dr2.getCost()) {
                return 0;
            } else if (dr1.getCost() < dr2.getCost()) {
                return -1;
            } else {
                return 1;
            }
        }
    }

}
