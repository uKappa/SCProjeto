import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.ParseException;
import java.util.Scanner;
import java.util.Map;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;


public class IoTServer {

	public static Auth authenticateUser(String username, String password) {
        String fileName = "users.txt";
        Map<String, String> users = new HashMap<>();
        System.out.println("entrei na função authenticateUser. server 21");

        try {
            // Read the existing user data from the text file
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    users.put(parts[0], parts[1]);
                }
            }
            reader.close();

            // Check if the username exists
            if (users.containsKey(username)) {
                String storedPassword = users.get(username);
                // Check if the password matches
                if (storedPassword.equals(password)) {
                    return Auth.OK_USER; // Authentication successful
                } else {
                    return Auth.PASSWORD_NO_MATCH; // Password doesn't match
                }
            } else {
                // Add the new user to the text file
                FileWriter writer = new FileWriter(fileName, true);
                writer.write(username + ":" + password + "\n");
                writer.close();
                return Auth.NEW_USER; // New user added successfully
            }
        } catch (IOException e) {
            e.printStackTrace();
            return Auth.ERROR; // Error occurred
        }
    }
	
    
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
 			
				// ler e escrever no ficheiro users
                Auth autenticado = authenticateUser(user_id,passwd);

				outStream.writeObject(autenticado);
				//outStream.writeBoolean(autenticado);
				System.out.println(autenticado);
                while (autenticado == Auth.PASSWORD_NO_MATCH) {
                    passwd = (String)inStream.readObject();
                    autenticado = authenticateUser(user_id,passwd);
                    System.out.println(autenticado);
                }
                int dev_id = (int)inStream.readObject();
                String nomeTamanho = (String)inStream.readObject();
                String[] nomeTamanhoSpt = nomeTamanho.split(" ");
                // TODO RESPOSTA

                String comando;
                boolean loop = true;
                while (loop) {
                    comando = (String)inStream.readObject();
                    System.out.print(user_id + ": ");
					System.out.println(comando);
                    String[] comandoSplit = comando.split(" ");

                    // TODO PROCESSAR COMANDOS AQUI

                    File dominios;
					FileWriter wr;
					String dContent = "";
					Scanner sc1;
					boolean erro = false;




                    if(comandoSplit[0].equals("CREATE")) {
                        boolean existe = false;
                        try {
                            dominios = new File("./dominios.txt");
							sc1 = new Scanner(dominios);
							while(sc1.hasNextLine()){
								String line = sc1.nextLine();
								dContent = dContent.concat(line + "\n");
								String[] dSplit = line.split("-");
								if (dSplit[0].equals(comandoSplit[1]))
									existe = true;
							}
							sc1.close();
							wr = new FileWriter("./dominios.txt");
                        } catch (Exception e) {
                            wr = new FileWriter("./dominios.txt");
                        }
                        
                        if (existe) {
                            outStream.writeObject("NOK");
                        } else {
                            dContent = dContent.concat(comandoSplit[1] + "-" + user_id + "-:-:\n");
                            outStream.writeObject("OK");
                        }
                        wr.write(dContent);
                        wr.close();
                    }








                    if(comandoSplit[0].equals("ADD")){
                        boolean existeD = false;
                        boolean perm = false;
                        boolean existeU = false;
                        boolean done = false;
                        try {
                            dominios = new File("./dominios.txt");
							sc1 = new Scanner(dominios);
							while(sc1.hasNextLine()){
								String line = sc1.nextLine();
                                String[] dSplit = line.split("-");
								dContent = dContent.concat(dSplit[0] + "-" + dSplit[1] + "-" + dSplit[2]);
								if (dSplit[0].equals(comandoSplit[2])){
                                    existeD = true;
                                    if (dSplit[1].equals(user_id)) {
                                        perm = true;
                                        BufferedReader reader = new BufferedReader(new FileReader("users.txt"));
                                        String line2;
                                        while ((line2 = reader.readLine()) != null && !existeU) {
                                            String[] parts = line2.split(":");
                                            if (parts[0].equals(comandoSplit[1])) {
                                                existeU = true;
                                                String[] usersAdded = dSplit[2].split(":");
                                                if (Arrays.stream(usersAdded).anyMatch(comandoSplit[1]::equals) || dSplit[1].equals(comandoSplit[1])) {
                                                    done = true;
                                                }
                                            }
                                        }
                                        reader.close();
                                        if (existeU && !done) {
                                            dContent = dContent.concat(comandoSplit[1] + ":-" + dSplit[3]+"\n");
                                        }
                                        else
                                        dContent = dContent.concat("-" + dSplit[3]+"\n");
							        }
                                    else
                                    dContent = dContent.concat("-" + dSplit[3]+"\n");
                                }else
                                dContent = dContent.concat("-" + dSplit[3]+"\n");
                            }
							sc1.close();
							wr = new FileWriter("./dominios.txt");
                        } catch (Exception e) {
                            wr = new FileWriter("./dominios.txt");
                        }
                        
                        if (!existeD) {
                            outStream.writeObject("NODM");
                        } else {
                            if (!perm) {
                                outStream.writeObject("NOPERM");
                            } else {
                                if (!existeU) {
                                    outStream.writeObject("NOUSER");
                                } else {
                                    outStream.writeObject("OK");
                                }
                            }
                        }
                        wr.write(dContent);
                        wr.close();
                    }




                    if(comandoSplit[0].equals("RD")){

                        boolean existeD = false;
                        boolean perm = false;
                        boolean permAux = false;
                        boolean done = false;
                        try {
                            dominios = new File("./dominios.txt");
							sc1 = new Scanner(dominios);
							while(sc1.hasNextLine()){
                                permAux = false;
								String line = sc1.nextLine();
								dContent = dContent.concat(line);
								String[] dSplit = line.split("-");
								if (dSplit[0].equals(comandoSplit[1])){
                                    existeD = true;
                                    if(user_id.equals(dSplit[1])){
                                        permAux = true;
                                        perm = true;
                                    }
                                    String[] usersSpt = dSplit[2].split(":");
                                    int i = 0;
                                    while (!permAux && i < usersSpt.length) {
                                        if (usersSpt[i].equals(user_id)){
                                            permAux = true;
                                            perm = true;
                                        }                                           
                                        i++;
                                    }
                                    if (permAux) {
                                        String[] devicesAdded = dSplit[3].split(":");
                                        for (String dev : devicesAdded) {
                                            if (dev.equals(Integer.toString(dev_id))) {
                                                done = true;
                                            }
                                        }
                                    }
                                }
                                
                                
                                
                                if (permAux && !done) 
                                    dContent = dContent.concat(":" + dev_id +"\n");
                                else
                                    dContent = dContent.concat("\n");
							}
							sc1.close();
							wr = new FileWriter("./dominios.txt");
                        } catch (Exception e) {
                            wr = new FileWriter("./dominios.txt");
                        }
                        
                        if (!existeD) {
                            outStream.writeObject("NODM");
                        } else {
                            if (!perm) {
                                outStream.writeObject("NOPERM");
                            } else {
                                outStream.writeObject("OK");
                            }
                            
                        }
                        wr.write(dContent);
                        wr.close();
                    }




                    if (comandoSplit[0].equals("ET")){
                        
                        try {
                            float temp = Float.parseFloat(comandoSplit[1]);
                        } catch (Exception e) {
                            outStream.writeObject("NOK");
                        }
                        outStream.writeObject("OK");
                    }






                    if (comandoSplit[0].equals("EI")){

                        outStream.writeObject("waiting");
                        Boolean existe = inStream.readObject().equals("existe");
                        if (existe) {
                            File img = new File("./ser/"+comandoSplit[1]);
                            FileOutputStream fout = new FileOutputStream(img);
                            OutputStream output = new BufferedOutputStream(fout);
                            byte[] buffer = new byte[1024];
                            int bytesRead;
                            int fileSize;

                            try {
                                fileSize = (int) inStream.readObject();
                                int totalSize = fileSize;

                                while (totalSize > 0) {
                                    if (totalSize >= 1024) {
                                        bytesRead = inStream.read(buffer,0,1024);
                                    } else {
                                        bytesRead = inStream.read(buffer,0,totalSize);
                                    }
                                    output.write(buffer,0,bytesRead);
                                    totalSize -= bytesRead;
                                }
                                output.close();
                                fout.close();
                                
                            } catch (Exception e) {
                                outStream.writeObject("NOK");
                            }
                            output.write(buffer, 0, 1024);
                            outStream.writeObject("OK");
                        } else {
                            outStream.writeObject("NOK");
                        }
                        

                    }
                    




                    if (comandoSplit[0].equals("exit") || comandoSplit[0].equals("e")) {
                        loop = false;
						System.out.println("User " + user_id + " desconectado");
						outStream.writeObject("Foi desconectado com sucesso");                        
                    }
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
