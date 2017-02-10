package org.fiware.cybercaptor.server.topology;

import org.fiware.cybercaptor.server.topology.asset.Host;

public class NDNFace
{
	/**
	 * The host
	 */
	Host host;
	
	/**
	 * The face name
	 */
	String name;

	public NDNFace(Host host, String name) {
		this.host = host;
		this.name = name;
		host.addNDNFace(this);
	}

	public String getName() {
		return name;
	}

	public Host getHost() {
		return host;
	}
	
}
