package edu.wisc.cs.sdn.vnet.rt;

import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;


public class ArpEntry 
{
	private MACAddress macAddr;
	private int ip;
	private long timestamp;
	public ArpEntry(MACAddress macAddr, int ip){
		this.macAddr = macAddr;
		this.ip = ip;
		this.timestamp = System.currentTimeMillis();
	}

	public MACAddress getMac(){ 
		return this.macAddr;
	}
	
	public int getIp(){ 
		return this.ip; 
	}

	public long getTimeAdded(){ 
		return this.timestamp; 
	}
	
	public String toString(){
		return String.format("%s \t%s", IPv4.fromIPv4Address(this.ip), this.macAddr.toString());
	}
}
