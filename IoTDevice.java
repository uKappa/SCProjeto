import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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

        int dev_id = Integer.parseInt(args[1]);
        String user_id = args[2];

        String passwd = "1234";

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
            socket = new Socket(host,port);

            outStream = new ObjectOutputStream(socket.getOutputStream());
			inStream = new ObjectInputStream(socket.getInputStream());

            outStream.writeObject(user_id);
            outStream.writeObject(passwd);

            String comand = "";
            System.out.println("Comandos: ");
            System.out.println("CREATE <dm>  # Criar domínio - utilizador é Owner");
            System.out.println("ADD <user1> <dm> # Adicionar utilizador <user1> ao domínio <dm>");
            System.out.println("RD <dm>  # Registar o Dispositivo atual no domínio <dm>");
            System.out.println("ET <float> # Enviar valor <float> de Temperatura para o servidor");
            System.out.println("EI <filename.jpg> # Enviar Imagem <filename.jpg> para o servidor");
            System.out.println("RT <dm> # Receber as últimas medições de Temperatura de cada dispositivo do domínio <dm>, desde que o utilizador tenha permissões");
            System.out.println("RI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo <userid>:<dev_id> do servidor, desde que o utilizador tenha permissões");
			System.out.println("exit");
            while(!(comand.equals("exit") || comand.equals("e"))){
                System.out.println("Insira um comando: ");
                comand = sc.nextLine();
                outStream.writeObject(comand);
                String[] cmdSpt = comand.split(" ");
            }
            sc.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        
        outStream.close();
		inStream.close();
 			
		socket.close();

    }
}
