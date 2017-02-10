package org.fiware.cybercaptor.server.topology;

import org.fiware.cybercaptor.server.flowmatrix.FlowMatrixLine;
import org.fiware.cybercaptor.server.topology.asset.Host;
import org.jdom2.Element;

/*
 * Class representing a NDN link between 2 hosts, regardless the underlying protocol
 * (can be NDN over IP)
 */

public class NDNLink
{
	NDNFace source;
	NDNFace destination;
	
	public NDNLink(NDNFace source, NDNFace destination)
	{
		this.source = source;
		this.destination = destination;
	}
	
	/**
     * Create a NDN link from a XML DOM element
     *
     * @param element  the XML DOM element
     * @param topology the network topology
     */
    public NDNLink(Element element, Topology topology) throws Exception {
    	if (element == null)
            throw new IllegalArgumentException("The NDN link element is null");
    	String host_src_name = element.getChildText("host-src");
    	String host_dst_name = element.getChildText("host-dst");
    	String face_src_name = element.getChildText("face-src");
    	String face_dst_name = element.getChildText("face-dst");
    	
    	Host host_src = topology.existingHostByName(host_src_name);
    	Host host_dst = topology.existingHostByName(host_dst_name);
    	
    	source = new NDNFace(host_src, face_src_name);
    	destination = new NDNFace(host_dst, face_dst_name);
    }
    
    public Element toDomXMLElement() throws Exception
    {
    	Element root = new Element("ndn-link");
    	Element host_src = new Element("host-src");
    	Element host_dst = new Element("host-dst");
    	Element face_src = new Element("face-src");
    	Element face_dst = new Element("face-dst");
    	
    	face_src.setText(source.getName());
    	face_dst.setText(destination.getName());
    	host_src.setText(source.getHost().getName());
    	host_dst.setText(destination.getHost().getName());
    	
    	root.addContent(host_src);
    	root.addContent(face_src);
    	root.addContent(host_dst);
    	root.addContent(face_dst);
    	
    	return root;
    }

	public NDNFace getSource() {
		return source;
	}

	public void setSource(NDNFace source) {
		this.source = source;
	}

	public NDNFace getDestination() {
		return destination;
	}

	public void setDestination(NDNFace destination) {
		this.destination = destination;
	}
	
}
