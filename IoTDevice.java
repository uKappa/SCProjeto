import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class IoTDevice {
    public static void main(String[] args) throws IOException {
        Socket socket = null;

        String serverAddress = args[0];
        int port;
        String[] split = serverAddress.split(":");
        String host = split[0];
        Scanner sc = new Scanner(System.in);
        if (serverAddress.contains(":")){
            port = Integer.parseInt(split[1]);
        }
        else{
            port = 12345;
        }

        String trustStore = args[1];
        String keystore = args[2];
        String pswKeyS = args[3];
        int dev_id = Integer.parseInt(args[4]);
        String user_id = args[5];

        String passwd;

        System.out.println("Insira a sua password: ");
        passwd = sc.nextLine();

        try {
            socket = new Socket(host,port);
        } catch (IOException e) {
            System.err.println(e.getMessage());
			System.exit(-1);
        }

        System.out.println("Ligação estabelecida");
        ObjectOutputStream outStream = null;
		ObjectInputStream inStream = null;
        
        try {

            outStream = new ObjectOutputStream(socket.getOutputStream());
			inStream = new ObjectInputStream(socket.getInputStream());

            outStream.writeObject(user_id);
            outStream.writeObject(passwd);

            System.out.println();   
            try {
                Auth aut = (Auth) inStream.readObject();
                if(aut == Auth.PASSWORD_NO_MATCH) {
                    System.out.println(aut.getMessage());
                    System.out.println("Insira a sua password: ");
                    passwd = sc.nextLine();
                    outStream.writeObject(passwd);
                }
                System.out.println(aut.getMessage());
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
            outStream.writeObject(dev_id);
            System.out.println("Insira nome e tamnaho do ficheiro executável IoTDevice <nome> <tamanho>: ");
            String nomeTamanho = sc.nextLine();
            // TODO erro no formato
            outStream.writeObject(nomeTamanho);

            String command = "";

            if ((boolean)inStream.readObject()) {
                command = "e";
                outStream.writeObject(command);
                System.out.println(inStream.readObject());
            }else{

                System.out.println("Comandos: ");
                System.out.println("CREATE <dm>  # Criar domínio - utilizador é Owner");
                System.out.println("ADD <user1> <dm> # Adicionar utilizador <user1> ao domínio <dm>");
                System.out.println("RD <dm>  # Registar o Dispositivo atual no domínio <dm>");
                System.out.println("ET <float> # Enviar valor <float> de Temperatura para o servidor");
                System.out.println("EI <filename.jpg> # Enviar Imagem <filename.jpg> para o servidor");
                System.out.println("RT <dm> # Receber as últimas medições de Temperatura de cada dispositivo do domínio <dm>, desde que o utilizador tenha permissões");
                System.out.println("RI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo <userid>:<dev_id> do servidor, desde que o utilizador tenha permissões");
                System.out.println("exit");


            }


            while(!(command.equals("exit") || command.equals("e"))){
                System.out.println("Insira um comando: ");
                command = sc.nextLine();
                outStream.writeObject(command);
                String[] cmdSpt = command.split(" ");



                if (cmdSpt[0].equals("EI")) {
                    if (inStream.readObject().equals("waiting")) {
                        try {
                            File img = new File("./cli/"+cmdSpt[1]);
                            FileInputStream fin = new FileInputStream(img);
                            outStream.writeObject("existe");
                            InputStream input = new BufferedInputStream(fin);
                            outStream.writeObject((int) img.length());
                            byte[] buffer = new byte[1024];
                            int bytesRead;
                            while ((bytesRead = input.read(buffer)) != -1) {
                                outStream.write(buffer, 0, bytesRead);
                            }
                            input.close();
                        } catch (Exception e) {
                            outStream.writeObject("não existe");
                            System.out.println("jpg não existe");
                        }
                    }         
                }




                if (cmdSpt[0].equals("RT")) {
                    if (inStream.readObject().equals("waiting")){
                        File tempFile = new File("./cli/temperature_data.txt");
                        FileOutputStream fout = new FileOutputStream(tempFile);
                        OutputStream output = new BufferedOutputStream(fout);
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        long fileSize;
                        try {
                            fileSize = (long) inStream.readObject();
                            int totalSize = Math.toIntExact(fileSize);

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
                            
                        }
                        output.write(buffer, 0, 1024);
                    }
                }





                if (cmdSpt[0].equals("RI")) {
                    if (inStream.readObject().equals("waiting")){
                        String imgName = (String)inStream.readObject();
                        File img = new File("./cli/" + imgName);
                        FileOutputStream fout = new FileOutputStream(img);
                        OutputStream output = new BufferedOutputStream(fout);
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        long fileSize;
                        try {
                            fileSize = (long) inStream.readObject();
                            int totalSize = Math.toIntExact(fileSize);

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
                            
                        }
                        output.write(buffer, 0, 1024);
                    }
                }



                


                System.out.println(inStream.readObject());
            }
            sc.close();

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        
        outStream.close();
		inStream.close();
 			
		socket.close();

    }
}
