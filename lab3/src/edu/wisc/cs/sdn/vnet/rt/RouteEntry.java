package edu.wisc.cs.sdn.vnet.rt;

import net.floodlightcontroller.packet.IPv4;
import edu.wisc.cs.sdn.vnet.Iface;


public class RouteEntry 
{
	private int destAddr;
	private int gateAddr;
	private int maskAddr;
	private Iface iface;
	public int num;
	public RouteEntry(int destAddr, int gateAddr, int maskAddr, Iface iface){
		this.destAddr = destAddr;
		this.gateAddr = gateAddr;
		this.maskAddr = maskAddr;
		this.iface = iface;
		this.num = 0;
	}
	
	public int getDestinationAddress(){ 
		return this.destAddr; 
	}
	
	public int getGatewayAddress(){ 
		return this.gateAddr; 
	}
	
	public int getMaskAddress(){ 
		return this.maskAddr; 
	}
	
	public Iface getInterface(){ 
		return this.iface; 
	}

    public void setInterface(Iface iface){ 
		this.iface = iface; 
	}

    public void setGatewayAddress(int gateAddr){ 
		this.gateAddr = gateAddr; 
	}
	public String toString(){
		return String.format("%s \t%s \t%s \t%s", IPv4.fromIPv4Address(this.destAddr), IPv4.fromIPv4Address(this.gateAddr), IPv4.fromIPv4Address(this.maskAddr), this.iface.getName());
	}
}
