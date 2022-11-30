package edu.wisc.cs.sdn.vnet.sw;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.MACAddress;


public class MACTableEntry 
{
	private MACAddress macAddr;
	private Iface iface;
	private long timeStamp;

	public MACTableEntry(MACAddress macAddr, Iface iface){
		this.macAddr = macAddr;
		this.iface = iface;
		this.timeStamp = System.currentTimeMillis();
	}
	
	public void update(Iface iface){
		this.iface = iface;
		this.timeStamp = System.currentTimeMillis();
	}
	
	public MACAddress getMACAddress(){ 
		return this.macAddr; 
	}

	public Iface getInterface(){ 
		return this.iface; 
	}
	
	public long getTimeUpdated(){ 
		return this.timeStamp; 
	}
}
