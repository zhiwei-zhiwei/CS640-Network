package edu.wisc.cs.sdn.vnet.sw;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.MACAddress;

public class MACTable implements Runnable
{
	private Map<MACAddress,MACTableEntry> map;
	private Thread timeout;
	public MACTable(){
		this.map = new ConcurrentHashMap<MACAddress, MACTableEntry>();
		timeout = new Thread(this);
		timeout.start();
	}
	
	public void insert(MACAddress macAddr, Iface iface){
		MACTableEntry entry = this.lookup(macAddr);
		if(entry == null) {
			entry = new MACTableEntry(macAddr, iface);
			this.map.put(macAddr, entry); 
		} else { 
			entry.update(iface); 
		}
	}
	
	public MACTableEntry lookup(MACAddress macAddr) {
		return this.map.get(macAddr);
	}
	
	public void run(){
		for(;;)
		{
			try { 
				Thread.sleep(1000); 
			} catch (InterruptedException e) { 
				break;
			}
			for (MACTableEntry entry : this.map.values())
			{
				if ((System.currentTimeMillis() - entry.getTimeUpdated()) > 15 * 1000) {
					this.map.remove(entry.getMACAddress()); 
				}
			}
		}
	}
}
