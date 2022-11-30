package edu.wisc.cs.sdn.vnet.rt;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;


public class ArpCache
{		
	private Map<Integer,ArpEntry> map;
	private int db;
	public ArpCache(){ 
		this.map = new ConcurrentHashMap<Integer,ArpEntry>(); 
		this.db = 0;
	}

	public void insert(MACAddress mac, int ip){ 
		this.map.put(ip, new ArpEntry(mac, ip)); 
	}
	
	public ArpEntry lookup(int ip){ 
		return this.map.get(ip);
	}
	
	public boolean load(String filename)
	{
		BufferedReader reader;
		try {
			FileReader fileReader = new FileReader(filename);
			reader = new BufferedReader(fileReader);
		} catch (FileNotFoundException e) {
			System.err.println(e.toString());
			return false;
		}
		for (;;){
			String line = null;
			try { 
				line = reader.readLine(); 
			} catch (IOException e) {
				System.err.println(e.toString());
				try{reader.close();}catch (Exception e1){break;}
				return false;
			}
			if (line == null){
				break;
			}
			Pattern pattern = Pattern.compile(String.format("%s\\s+%s", "(\\d+\\.\\d+\\.\\d+\\.\\d+)", "([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})"));
			Matcher matcher = pattern.matcher(line);
			if (!matcher.matches() || matcher.groupCount() != 2){
				System.err.println("Invalid entry in ARP cache file");
				try{reader.close();}catch (Exception e2){break;}
				return false;
			}
			int ip = IPv4.toIPv4Address(matcher.group(1));
			if (ip == 0){
				System.err.println("Error loading ARP cache, cannot convert "+ matcher.group(1) + " to valid IP");
				try{reader.close();}catch (Exception e3){break;}
				return false;
			}
			MACAddress mac = null;
			try{ 
				mac = MACAddress.valueOf(matcher.group(2)); 
			} catch(IllegalArgumentException e) {
				System.err.println("Error loading ARP cache, cannot convert "+ matcher.group(3) + " to valid MAC");
				try{reader.close();}catch (Exception e4){break;}
				return false;
			}
			this.insert(mac, ip);
			db++;
		}
		try{reader.close();}catch (Exception e5){}
		return true;
	}
	
	public String toString()
	{
        String result = "IP\t\tMAC\n";
        for (ArpEntry entry : this.map.values()){ 
			result += entry.toString()+"\n"; 
		}
	    return result;
	}
}
