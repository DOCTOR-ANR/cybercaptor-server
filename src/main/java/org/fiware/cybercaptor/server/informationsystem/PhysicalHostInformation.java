package org.fiware.cybercaptor.server.informationsystem;

public class PhysicalHostInformation {
	
	/**
	 * The host name
	 */
	private String host = null;
	
	/**
	 * The hypervisor name (service name) running the VM on the host
	 */
	private String hypervisor = null;
	
	/**
	 * The user the hypervisor runs as
	 */
	private String user = null;
	
	public PhysicalHostInformation(String host, String hypervisor, String user)
	{
		this.host = host;
		this.hypervisor = hypervisor;
		this.user = user;
	}
	
	public String getHost()
	{
		return host;
	}
	
	public String getHypervisor()
	{
		return hypervisor;
	}
	
	public String getUser()
	{
		return user;
	}

}
