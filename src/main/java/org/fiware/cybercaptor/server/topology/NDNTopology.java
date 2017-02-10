package org.fiware.cybercaptor.server.topology;

import java.util.ArrayList;
import java.util.List;

import org.fiware.cybercaptor.server.flowmatrix.FlowMatrixLine;
import org.jdom2.Element;

public class NDNTopology
{
	List<NDNLink> links = new ArrayList<NDNLink>();
	
	/**
     * Create a NDN topology from a XML DOM element
     *
     * @param element  the XML DOM element
     * @param topology the network topology
     */
    public NDNTopology(Element element, Topology topology) throws Exception
    {
        if (element != null)
        {
            for (Element ndnLinkElement : element.getChildren("ndn-link"))
            {
                links.add(new NDNLink(ndnLinkElement, topology));
            }
        }
    }
    
    /**
     * Export the NDN topology to DOM XML element
     */
    public Element toDomXMLElement() throws Exception
    {
    	Element root = new Element("ndn-links");
    	for (NDNLink link : links)
    	{
    		root.addContent(link.toDomXMLElement());
    	}
    	return root;
    }
    
    /**
     * @return if it empty
     */
    public boolean isEmpty()
    {
    	return links.isEmpty();
    }
    
    /**
     * @return the link list
     */
    public List<NDNLink> getLinks()
    {
    	return links;
    }
}
