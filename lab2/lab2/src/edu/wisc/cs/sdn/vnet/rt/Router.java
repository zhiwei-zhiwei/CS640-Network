package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
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
		boolean typeCheck = (etherPacket.getEtherType() == Ethernet.TYPE_IPv4);
		if(typeCheck == true){
			IPv4 header = (IPv4) etherPacket.getPayload();
			// cast result to IPv4
			short checksum = header.getChecksum();
			header.setChecksum((short)0); // type of getChecksum is short, cast 0 to short type
			header.serialize(); 
			// header = header.deserialize(serializeHeader, 0, serializeHeader.length);
			if(checksum == header.getChecksum()){
				header.setTtl((byte)(header.getTtl() - 1)); // decrement the packet's TTL by 1
				if(header.getTtl() > 0){
					header.resetChecksum();
					etherPacket.setPayload(header);
					// make sure the TTL is bigger than 0, or drop
					for(Iface newiIface : interfaces.values()){

						if(newiIface.getIpAddress() == header.getDestinationAddress()){
							System.out.println(newiIface.getIpAddress());
							System.out.println(header.getDestinationAddress());
							// If the packet’s destination IP address exactly matches one of the interface’s IP addresses, drop
							return;
						}
					}
					RouteEntry temp = routeTable.lookup(header.getDestinationAddress());
					if(temp != null && temp != null){
						// You should use the lookup(...) method in the RouteTable class, which you implemented earlier, to obtain the RouteEntry that has the longest prefix match with the destination IP address.
						ArpEntry arpEntry = arpCache.lookup(header.getDestinationAddress());
						etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
						etherPacket.setSourceMACAddress(temp.getInterface().getMacAddress().toBytes());
						header.resetChecksum();
						sendPacket((etherPacket), temp.getInterface());
						
					} else {
						return;
					}
					
				} else {
					return;
				}
			} else {
				return;
			}
		} else {
			return;
		}
		
		/********************************************************************/
	}
}
