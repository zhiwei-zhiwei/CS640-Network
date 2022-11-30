package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;

import java.util.zip.Inflater;
import java.util.*;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device{

	private Map<MACAddress, SwitchTable> map = new HashMap<>(); 
	// establish a hashmap to store the host and port

	private static class SwitchTable {
		private Iface outIface;
		private long runTime; // check the time out

		public SwitchTable(Iface outIface){
			this.outIface = outIface;
		}

		public SwitchTable(long runTime){
			this.runTime = runTime;
		}
	}
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		MACAddress sourMac = etherPacket.getSourceMAC();
		MACAddress destMac = etherPacket.getDestinationMAC();
		SwitchTable switchTable = new SwitchTable(inIface);

		long startTime = System.currentTimeMillis();
		map.put(sourMac, switchTable); // put the information into the map

		if(map.containsKey(destMac)){
			// while the desitionation port already in the map
			SwitchTable destMacInfo = map.get(destMac);
			long endTime = System.currentTimeMillis(); // recored the current time to check the time out
			long totalTime = endTime - startTime;

			if(totalTime >= 15000){
				// timeout situation -> broadcast
				map.remove(destMac);
				for(Iface iface: interfaces.values()){
					// do broadcast
					if(inIface.equals(iface) == false){
						sendPacket(etherPacket, iface);
					}
				}
			}else{
				// fine situation -> forwarding
				sendPacket(etherPacket, destMacInfo.outIface);
			}
			
		}else{
			// if not find, broadcast to all
			for(Iface iface: interfaces.values()){
				// do broadcast
				if(inIface.equals(iface) == false){
					sendPacket(etherPacket, iface);
				}
			}
		}
		/********************************************************************/
	}
}
