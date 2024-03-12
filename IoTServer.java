import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class IoTServer {
    
    public static void main(String[] args) {
        System.out.println("servidor: main");
		IoTServer server = new IoTServer();
        int port;
        if (args.length==0) {
            port = 12345;
        } else {
            port = Integer.parseInt(args[0]);
        }

		server.startServer(port);
    }

    public void startServer (int port){
		ServerSocket sSoc = null;


		try {
			sSoc = new ServerSocket(port);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
         
		while(true) {
			try {
				Socket inSoc = sSoc.accept();
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
		    }
		    catch (IOException e) {
		        e.printStackTrace();
		    }
		    
		}
		//sSoc.close();
	}

    //Threads utilizadas para comunicacao com os clientes
	class ServerThread extends Thread {

		private Socket socket = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
			System.out.println("thread do server para cada cliente");
		}
 
		public void run(){
			try {
				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

				String user_id = null;
				String passwd = null;
			
				try {
					user_id = (String)inStream.readObject();
					passwd = (String)inStream.readObject();
                    System.out.println(user_id);
					System.out.println("thread: depois de receber a password e o user_id");
				}catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
 			
				// TODO AUTENTICAR
				

                String comando;
                boolean loop = true;
                while (loop) {
                    comando = (String)inStream.readObject();
                    System.out.print(user_id + ": ");
					System.out.println(comando);
                    String[] comandoSplit = comando.split(" ");

                    // TODO PROCESSAR COMANDOS AQUI

                    // if (comandoSplit[0].equals("ADD")) 
                }

				outStream.close();
				inStream.close();
 			
				socket.close();

			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
	}

}
