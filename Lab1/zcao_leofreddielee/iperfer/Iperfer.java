import java.net.*;
public class Iperfer{
    public static void main(String[] args) {
        boolean clientMode = false;
        if(args.length > 2){
            //System.out.println((args[0] == "-c"));
            if(args[0].equals("-c")){
                // client mode
                if(args[1].equals("-h")){
                    if (!args[2].equals("-p")){
                        InetAddress inet = null;
                        try { 
                            inet = InetAddress.getByName(args[2]); 
                        } catch (UnknownHostException e) {
                            System.out.println("Error: missing or additional arguments");
                            System.exit(0);
                        }
                        String IPAddress = inet.getHostAddress();
                        // System.out.println(IPAddress);
                        // make sure there is a hostname
                        if (args[3].equals("-p")){
                            if(1024 <= Integer.parseInt(args[4]) && Integer.parseInt(args[4]) <= 65535){
                                if(args[5].equals("-t")){
                                    if (Integer.parseInt(args[6])>0){
                                        clientMode = true;
                                        client(args[2], Integer.parseInt(args[4]), Integer.parseInt(args[6]));
                                    }
                                    else{
                                        System.out.println("Error: missing or additional arguments");
				                        System.exit(0);
                                    }
                                }
                                else{
                                    System.out.println("Error: missing or additional arguments");
				                    System.exit(0);
                                }
                            }else{
                                System.out.println("Error: port number must be in the range 1024 to 65535");
				                System.exit(0);
                            }
                        }
                        else{
                            System.out.println("Error: missing or additional arguments");
				            System.exit(0);
                        }
                    }
                    else{
                        System.out.println("Error: missing or additional arguments");
				        System.exit(0);
                    }
                }
                else{
                    System.out.println("Error: missing or additional arguments");
				    System.exit(0);
                }
            }
            else if(args[0].equals("-s")){
                // server mode
                    if(args[1].equals("-p")){
                    
                        if(1024 <= Integer.parseInt(args[2]) && Integer.parseInt(args[2]) <= 65535){
                                server(Integer.parseInt(args[2]));
                        }
                        else{
                            System.out.println("Error: missing or additional arguments");
				            System.exit(0);
                        }
                    }
                    else{
                        System.out.println("Error: missing or additional arguments");
				        System.exit(0);
                    }
                }
                else{
                    System.out.println("Error: missing or additional arguments");
				    System.exit(0);
                }
            }
            else{
                System.out.println("Error: missing or additional arguments");
				System.exit(0);
            }

    }

    public static void client(String hostName, int portNum, int time) {
       
        try{
            int dataSent = 0;
            byte[] dataChunk = new byte[1000];
            boolean timeUp = false;
            long currTime = System.currentTimeMillis();
            long totaltime = time * 1000;
            Socket echoSocket = new Socket(hostName, portNum);
            while(!timeUp){
                echoSocket.getOutputStream().write(dataChunk);
                dataSent += 1000;
                timeUp = (System.currentTimeMillis() - currTime) >= totaltime;
            }
            echoSocket.close();
            int totalSent = dataSent / 1000;
            double rate = (dataSent/(double) (time)) * 0.000008;
            System.out.println("received="+totalSent+" KB rate="+rate+" Mbps");
       } catch (Exception e) {
        // TODO: handle exception
        System.out.println("Error IO Exception from server");
		System.exit(1);
       }
    }

    public static void server(int portNum)  {
        try{
            
            long currTime = System.currentTimeMillis();
            int dataReceived = 0;
            byte[] dataChunk = new byte[1000];
            
            int checkCondition = 1; //getInputStream.read will read int range from 0 - 255, value -1 means return 
            ServerSocket serverSocket = new ServerSocket(portNum);
            Socket clientSocket = serverSocket.accept();
            while(true){
                checkCondition = clientSocket.getInputStream().read(dataChunk);
                if(checkCondition<0) {
                    break;
                }
                dataReceived += checkCondition;
            }
            clientSocket.close();
            serverSocket.close();
            long totalTime = (System.currentTimeMillis() - currTime) / 1000;
            int totalSent = dataReceived / 1000;
            double rate = (dataReceived/(double) (totalTime)) * 0.000008;
            System.out.println("received="+totalSent+" KB rate="+rate+" Mbps");
            
        } catch (Exception e) {
            // TODO: handle exception
            System.out.println("Error IO Exception from server");
		    System.exit(1);
        }
    }
}