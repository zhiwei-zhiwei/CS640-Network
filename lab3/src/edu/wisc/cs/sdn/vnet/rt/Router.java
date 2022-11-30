package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.util.*;
import java.util.concurrent.*;
import java.nio.ByteBuffer;

public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	private Map<Integer, List<Ethernet>> arp_Q;
	private Map<Integer, LocalRipEntry> ripEntries;
	private final boolean ARP_c = false;
	private final boolean RIP_c = false;
	private final int TIME_EXCEEDED = 0;
	private final int DEST_NET_UNREACHABLE = 1;
	private final int DEST_HOST_UNREACHABLE = 2;
	private final int DEST_PORT_UNREACHABLE = 3;
	private final int ICMP_ECHO_REPLY = 4;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arp_Q = new ConcurrentHashMap<Integer, List<Ethernet>>();
		this.ripEntries = new ConcurrentHashMap<Integer, LocalRipEntry>();
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
	public void loadRouteTable(String routeTableFile){
		if (!routeTable.load(routeTableFile, this)){
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
		if (!arpCache.load(arpCacheFile)){
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
		/* TODO: Handle packets											 */
		if(etherPacket.getEtherType() == Ethernet.TYPE_IPv4){
			IPv4 ip = (IPv4)etherPacket.getPayload();
			if (ip.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9")){
				if (ip.getProtocol() == IPv4.PROTOCOL_UDP) {
					if (((UDP)ip.getPayload()).getDestinationPort() == UDP.RIP_PORT){ 
						RIPv2 rip = (RIPv2)((UDP)ip.getPayload()).getPayload();
						this.handleRipPacket(rip.getCommand(), etherPacket, inIface);
					}
				}
			}
			this.handleIpPacket(etherPacket, inIface);
		} else if(etherPacket.getEtherType() == Ethernet.TYPE_ARP){
			this.handleArpPacket(etherPacket, inIface);
		}		
		/********************************************************************/
	}

	/*******************************************************************************
	***********************				  RIP 				************************
	*******************************************************************************/

	class LocalRipEntry
	{
		protected int addr, mask, next, metric;
		protected long timestamp;
		public LocalRipEntry(int addr, int mask, int next, int metric, long timestamp) {
			this.addr = addr;
			this.mask = mask;
			this.next = next;
			this.metric = metric;
			this.timestamp = timestamp;
		}
	}

	public void ripInit()  
	{
		for (Iface iface : this.interfaces.values()){
			ripEntries.put(iface.getSubnetMask() & iface.getIpAddress(), new LocalRipEntry(iface.getSubnetMask() & iface.getIpAddress(), iface.getSubnetMask(), 0, 0, -1));
			routeTable.insert(iface.getSubnetMask() & iface.getIpAddress(), 0, iface.getSubnetMask(), iface);
			sendRip(0, null, iface);
		}
		TimerTask from = new TimerTask(){
			public void run(){
				if (RIP_c) System.out.println("Send unsolicited RIP response");
				for (Iface iface : interfaces.values())
				{sendRip(2, null, iface); }
			}
		};
		TimerTask to = new TimerTask(){
			public void run(){
				for (LocalRipEntry entry : ripEntries.values()) {
					if (entry.timestamp != -1 && System.currentTimeMillis() - entry.timestamp >= 30000){	
						if (RIP_c) System.out.println("Table entry timeout: " + IPv4.fromIPv4Address(entry.addr));
						ripEntries.remove(entry.addr & entry.mask);
						routeTable.remove(entry.addr, entry.mask);
					}
				}
			}
		};
		Timer timer = new Timer(true);
		timer.schedule(from, 0, 10000);
		timer.schedule(to, 0, 1000);
	}

	private void handleRipPacket(byte type, Ethernet etherPacket, Iface inIface) {
		if(type == RIPv2.COMMAND_REQUEST){
			if (RIP_c) System.out.println("Send RIP response");
			sendRip(1, etherPacket, inIface);
		}else if(type == RIPv2.COMMAND_RESPONSE){
			IPv4 ip = (IPv4)etherPacket.getPayload();
				if (RIP_c) System.out.println("Handle RIP response from " + IPv4.fromIPv4Address(ip.getSourceAddress()));
				for (RIPv2Entry entry : ((RIPv2)((UDP)ip.getPayload()).getPayload()).getEntries()) {
					int ipAddr = entry.getAddress();
					int mask = entry.getSubnetMask();
					int next = ip.getSourceAddress();
					int metric = entry.getMetric() + 1;
					if (metric >= 17) { metric = 16; }
					int netAddr = ipAddr & mask;
					synchronized(this.ripEntries){
						if (ripEntries.containsKey(netAddr)) {
							ripEntries.get(netAddr).timestamp = System.currentTimeMillis();
							if (metric < ripEntries.get(netAddr).metric){
								ripEntries.get(netAddr).metric = metric;
								if (RIP_c) System.out.println("Update RouteEntry " +
								IPv4.fromIPv4Address(ipAddr) + " " + IPv4.fromIPv4Address(next) + " " + IPv4.fromIPv4Address(mask) + " " + inIface.toString());
								this.routeTable.update(ipAddr, mask, next, inIface);
							}
							if (metric >= 16) {
								RouteEntry bestMatch = this.routeTable.lookup(ipAddr);
								if (inIface.equals(bestMatch.getInterface())) {
									ripEntries.get(netAddr).metric = 16;
									if (null != bestMatch) 
									{this.routeTable.remove(ipAddr, mask);}
								}
							}
						}
						else{
							ripEntries.put(netAddr, new LocalRipEntry(ipAddr, mask, next, metric, System.currentTimeMillis()));
							if (metric < 16) {
								if (RIP_c) System.out.println("Insert new RouteEntry " +
								IPv4.fromIPv4Address(ipAddr) + " " + IPv4.fromIPv4Address(next) + " " + IPv4.fromIPv4Address(mask) + " " + inIface.toString());
								this.routeTable.insert(ipAddr, next, mask, inIface);
							}
						}
					}
				}
		}
				

		
	}

	private void sendRip(int type, Ethernet etherPacket, Iface iface) {
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();
		ether.setSourceMACAddress(iface.getMacAddress().toBytes());
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(iface.getIpAddress());
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		if(type == 0){
			rip.setCommand(RIPv2.COMMAND_REQUEST);
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
			ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
		}else if(type == 1){
			IPv4 ipPacket = (IPv4)etherPacket.getPayload();
			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			ether.setDestinationMACAddress(ether.getSourceMACAddress());
			ip.setDestinationAddress(ipPacket.getSourceAddress());
		}else if(type == 2){
			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
			ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
		}

		List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>();
		synchronized(this.ripEntries) {
			for (LocalRipEntry localEntry : ripEntries.values()){
				RIPv2Entry entry = new RIPv2Entry(localEntry.addr, localEntry.mask, localEntry.metric);
				entries.add(entry);
			}
		}
		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);
		rip.setEntries(entries);
		if (RIP_c) System.out.println("Sending RIP packet to " + IPv4.fromIPv4Address(ip.getDestinationAddress()));
		sendPacket(ether, iface);
	}

	/*******************************************************************************
	***********************				  IP 				************************
	*******************************************************************************/

	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4){ return; }
		for (Iface iface : this.interfaces.values()) {
			arpCache.insert(iface.getMacAddress(), iface.getIpAddress());
		}
		IPv4 packet = (IPv4)etherPacket.getPayload();
		System.out.println("Handle IP packet");
		short origCksum = packet.getChecksum();
		packet.resetChecksum();
		byte[] serialized = packet.serialize();
		packet.deserialize(serialized, 0, serialized.length);
		if (origCksum == packet.getChecksum()){
			packet.setTtl((byte)(packet.getTtl()-1));
		if (packet.getTtl() == 0){ 
			if (ARP_c) System.out.println("TIME_EXCEEDED");
			sendICMP(TIME_EXCEEDED, etherPacket, inIface);
			return; 
		}
		packet.resetChecksum();
		for (Iface iface : this.interfaces.values()) {
			if (packet.getDestinationAddress() == iface.getIpAddress()) {
				byte protocol = packet.getProtocol();
				if(protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP) {
					if (ARP_c) System.out.println("DEST_PORT_UNREACHABLE");
					sendICMP(DEST_PORT_UNREACHABLE ,etherPacket, inIface);
				} 
				else if (protocol == IPv4.PROTOCOL_ICMP) {
					ICMP icmpPacket = (ICMP) packet.getPayload();
					if(icmpPacket.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
						if (ARP_c) System.out.println("ICMP_ECHO_REPLY");
						sendICMP(ICMP_ECHO_REPLY ,etherPacket, inIface);
					}
				}
				return;
			}
		}
		this.forwardIpPacket(etherPacket, inIface);
		}
		
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface){
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4){ return; }
		System.out.println("Forward IP packet");
		if (this.routeTable.lookup(((IPv4)etherPacket.getPayload()).getDestinationAddress()) == null){
			if (ARP_c) System.out.println("DEST_NET_UNREACHABLE");
			sendICMP(DEST_NET_UNREACHABLE, etherPacket, inIface);
			return; 
		}
		if (this.routeTable.lookup(((IPv4)etherPacket.getPayload()).getDestinationAddress()).getInterface() == inIface) { return; }
		etherPacket.setSourceMACAddress(this.routeTable.lookup(((IPv4)etherPacket.getPayload()).getDestinationAddress()).getInterface().getMacAddress().toBytes());
		int next = this.routeTable.lookup(((IPv4)etherPacket.getPayload()).getDestinationAddress()).getGatewayAddress();
		if (next==0) { next = ((IPv4)etherPacket.getPayload()).getDestinationAddress(); }
		ArpEntry arpEntry = this.arpCache.lookup(next);
		if (null == arpEntry){ 
			if (ARP_c) System.out.println("arp miss ip");
			sendICMP(DEST_HOST_UNREACHABLE, etherPacket, inIface);
			handleArpMiss(next, etherPacket, inIface, this.routeTable.lookup(((IPv4)etherPacket.getPayload()).getDestinationAddress()).getInterface());
			return; 
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
		this.sendPacket(etherPacket, this.routeTable.lookup(((IPv4)etherPacket.getPayload()).getDestinationAddress()).getInterface());
	}

	/*******************************************************************************
	***********************				  ARP 				************************
	*******************************************************************************/

	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
		for (Iface iface : this.interfaces.values()) {
			if (ByteBuffer.wrap(((ARP)etherPacket.getPayload()).getTargetProtocolAddress()).getInt() == iface.getIpAddress()) {
				if (((ARP)etherPacket.getPayload()).getOpCode() == ARP.OP_REQUEST) {
					if (ARP_c) System.out.println("ArpRequest received");
					sendArp(0, 1, etherPacket, inIface, inIface);
					break;
				}
				else if (((ARP)etherPacket.getPayload()).getOpCode() == ARP.OP_REPLY) {
					if (ARP_c) System.out.println("ArpReply received");
					arpCache.insert(MACAddress.valueOf(((ARP)etherPacket.getPayload()).getSenderHardwareAddress()), ByteBuffer.wrap(((ARP)etherPacket.getPayload()).getSenderProtocolAddress()).getInt());
					if (ARP_c) System.out.println("Insert arp entry \n" + arpCache.toString());
					synchronized(arp_Q){
						if (ARP_c) {
							for (Map.Entry<Integer, List<Ethernet>> qEntry: arp_Q.entrySet())
								System.out.println(IPv4.fromIPv4Address(qEntry.getKey()) + " :: " + IPv4.fromIPv4Address(ByteBuffer.wrap(((ARP)etherPacket.getPayload()).getSenderProtocolAddress()).getInt()) + " :: " + qEntry.getValue().size());
						}
						List<Ethernet> queue = arp_Q.remove(ByteBuffer.wrap(((ARP)etherPacket.getPayload()).getSenderProtocolAddress()).getInt());
						if (queue != null) {
							if (ARP_c) System.out.println("Send pending packets");
							for (Ethernet ether : queue) {
								ether.setDestinationMACAddress(MACAddress.valueOf(((ARP)etherPacket.getPayload()).getSenderHardwareAddress()).toBytes());
								sendPacket(ether, inIface);
							}
						}
					}
				}
			}
		}
	}

	private void sendArp(int ip, int type, Ethernet etherPacket, Iface inIface, Iface outIface) {
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte)4);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		if(type == 0){
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
			arp.setOpCode(ARP.OP_REQUEST);
			arp.setTargetHardwareAddress(Ethernet.toMACAddress("00:00:00:00:00:00"));
			arp.setTargetProtocolAddress(ip);
		}else if(type == 1){
			ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		arp.setOpCode(ARP.OP_REPLY);
			arp.setTargetHardwareAddress(((ARP)etherPacket.getPayload()).getSenderHardwareAddress());
			arp.setTargetProtocolAddress(((ARP)etherPacket.getPayload()).getSenderProtocolAddress());
		}else{
			return;
		}		
		ether.setPayload(arp);
		if (ARP_c) System.out.println("Send ARP Packet");
		this.sendPacket(ether, outIface);
	}

	private void handleArpMiss(final int ip, final Ethernet etherPacket, final Iface inIface, final Iface outIface) {
		Integer dstAddr = new Integer(((IPv4)etherPacket.getPayload()).getDestinationAddress());
		if (this.routeTable.lookup(dstAddr) == null){ return; }
		int temp = this.routeTable.lookup(dstAddr).getGatewayAddress();
		if (temp == 0){ temp = dstAddr; }
		 int next = temp;
		synchronized(arp_Q) {
			if (arp_Q.containsKey(next)) {
				List<Ethernet> queue = arp_Q.get(next);
				queue.add(etherPacket);
			}
			else {
				List<Ethernet> queue = new ArrayList<Ethernet>();
				queue.add(etherPacket);
				arp_Q.put(next, queue);
				TimerTask task = new TimerTask(){
					int counter = 0;
					public void run(){
						if (null != arpCache.lookup(next)) { 
							this.cancel(); 
						}
						else {
							if (counter > 2) {
								if (ARP_c) System.out.println("TimeOut\n" + arpCache.toString());
								arp_Q.remove(next);
								sendICMP(DEST_HOST_UNREACHABLE, etherPacket, inIface);
								this.cancel();
							} 
							else {
								if (ARP_c) System.out.println("Timer  " + counter);
								sendArp(ip, 0, etherPacket, inIface, outIface);
								counter++;
							}
						}
					}
				};
				Timer timer = new Timer(true);
				timer.schedule(task, 0, 1000);
			}
		}
	}

	/*******************************************************************************
	***********************				  ICMP 				************************
	*******************************************************************************/

	private void sendICMP(int type, Ethernet etherPacket, Iface inIface){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		//RouteEntry bestMatch = this.routeTable.lookup((((IPv4)etherPacket.getPayload()).getSourceAddress()));
		if (null == this.routeTable.lookup((((IPv4)etherPacket.getPayload()).getSourceAddress()))){  	
			if (ARP_c) System.out.println("No best match");
			return;   
		}

		int next = this.routeTable.lookup((((IPv4)etherPacket.getPayload()).getSourceAddress())).getGatewayAddress();
		if (next == 0){ next = (((IPv4)etherPacket.getPayload()).getSourceAddress()); }
		if (this.arpCache.lookup(next) == null){  	
			if (ARP_c) System.out.println("arp miss icmp");
			handleArpMiss(next, etherPacket, inIface, inIface);
			return;   
		}
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(this.arpCache.lookup(next).getMac().toBytes());
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setDestinationAddress(((IPv4)etherPacket.getPayload()).getSourceAddress());
		byte[] temp_data;
		if (ICMP_ECHO_REPLY != type) {
			ip.setSourceAddress(inIface.getIpAddress());
			byte[] ipHP = ((IPv4)etherPacket.getPayload()).serialize();
			int ipHLength = ((IPv4)etherPacket.getPayload()).getHeaderLength() * 4;
			temp_data = new byte[4 + ipHLength + 8];
			Arrays.fill(temp_data, 0, 4, (byte)0);
			for (int i = 0; i < ipHLength + 8; i++) 
				{ temp_data[i + 4] = ipHP[i]; }
		}
		else { 
			ip.setSourceAddress(((IPv4)etherPacket.getPayload()).getDestinationAddress());
			temp_data = ((ICMP)((IPv4)etherPacket.getPayload()).getPayload()).getPayload().serialize();
		}
		if(type == TIME_EXCEEDED){
			icmp.setIcmpType((byte)11);
			icmp.setIcmpCode((byte)0);
		} else if(type == DEST_NET_UNREACHABLE){
			icmp.setIcmpType((byte)3);
			icmp.setIcmpCode((byte)0);
		}else if(type == DEST_HOST_UNREACHABLE){
			icmp.setIcmpType((byte)3);
			icmp.setIcmpCode((byte)1);
		}else if(type == DEST_PORT_UNREACHABLE){
			icmp.setIcmpType((byte)3);
			icmp.setIcmpCode((byte)3);
		}else if(type == ICMP_ECHO_REPLY){
			icmp.setIcmpType((byte)0);
			icmp.setIcmpCode((byte)0);
		}else{return;}
		
		data.setData(temp_data);
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		if (ARP_c) System.out.println("Send ICMP");
		this.sendPacket(ether, inIface);
	}
}
