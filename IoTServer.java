import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import java.util.Map;
import java.util.Random;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;


public class IoTServer {

    private List<User> users = new ArrayList<>();
    private static String apiKey;
    private Map<Integer, Float> deviceTemperatures = new HashMap<>();
    private static final String ALGORITHM2 = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    private static final int ITERATIONS = 10000;

    private static final byte[] SALT = {

    (byte) 0x1a, (byte) 0x5c, (byte) 0x9a, (byte) 0x12,

    (byte) 0x74, (byte) 0xfa, (byte) 0x18, (byte) 0x29

    }; // Hardcoded salt

    private static final int KEY_LENGTH = 128;

    private static final String ALGORITHM = "PBEWithHmacSHA256AndAES_128";
                                
    private static final int NONCE_LENGTH = 8;

    // Gerar nonce aleatório de 8 bytes
    private long generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonceBytes = new byte[NONCE_LENGTH];
        random.nextBytes(nonceBytes);
        return bytesToLong(nonceBytes);
    }

    // Converter bytes para long
    private long bytesToLong(byte[] bytes) {
        long result = 0;
        for (int i = 0; i < bytes.length; i++) {
            result <<= 8;
            result |= (bytes[i] & 0xFF);
        }
        return result;
    }

    private static final String TWO_FACTOR_AUTH_API_URL = "https://lmpinto.eu.pythonanywhere.com/2FA";

    // Método para gerar um código C2FA aleatório de cinco dígitos
    private static String generateC2FA() {
        Random random = new Random();
        int c2fa = random.nextInt(100000); // Gera um número aleatório entre 0 e 99999
        return String.format("%05d", c2fa); // Formata o número como uma string de cinco dígitos com zeros à esquerda, se necessário
    }

    // Método para enviar o código C2FA por e-mail ao utilizador
    private static void sendC2FAByEmail(String userEmail, String c2fa, String apiK) throws IOException {
        String urlString = TWO_FACTOR_AUTH_API_URL + "?e=" + userEmail + "&c=" + c2fa + "&a=" + apiK;
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            System.out.println("C2FA enviado por e-mail com sucesso para " + userEmail);
        } else {
            System.out.println("Falha ao enviar o C2FA por e-mail para " + userEmail);
        }
    }
/* 
    private byte[] calculateHash(byte[] nonce) throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        File device = new File("IotDevice.java");
        byte[] data = fileToByteArray(device);
        digest.update(data);
        digest.update(nonce);
        return digest.digest();
    } */

    private static byte[] fileToByteArray(File file) throws IOException {
        // Verifica se o arquivo existe
        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("Arquivo inválido: " + file.getPath());
        }
    
        // Cria um fluxo de entrada para ler os bytes do arquivo
        FileInputStream fis = new FileInputStream(file);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
        // Lê os bytes do arquivo e escreve-os no ByteArrayOutputStream
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
    
        // Fecha os fluxos de entrada
        fis.close();
        baos.close();
    
        // Retorna o array de bytes resultante
        return baos.toByteArray();
    }


	public static Auth authenticateUser(String username, String password) {
        String fileName = "users.txt";
        Map<String, String> users = new HashMap<>();
        //System.out.println("entrei na função authenticateUser. server 21");

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

    // Method to change image name for a specific user with given user ID and device ID
    public void changeUserImageName(String userId, int deviceId, String newImgName) {
        for (User user : users) {
            if (user.getUserId().equals(userId) && user.getDeviceId() == deviceId) {
                user.setImgName(newImgName);
                System.out.println("Image name updated for user " + userId + " with device ID " + deviceId);
                return; // Exit loop once user is found and image name is updated
            }
        }
        // If user with given ID and device ID pair is not found
        System.out.println("User with ID " + userId + " and device ID " + deviceId + " not found.");
    }

    // Method to disconnect a specific user with given user ID and device ID
    public void disconnectUser(String userId, int deviceId) {
        for (User user : users) {
            if (user.getUserId().equals(userId) && user.getDeviceId() == deviceId) {
                user.setConectado(false); // Setting connected attribute to false
                System.out.println("User " + userId + " with device ID " + deviceId + " disconnected");
                return; // Exit loop once user is found and disconnected
            }
        }
        // If user with given ID and device ID pair is not found
        System.out.println("User with ID " + userId + " and device ID " + deviceId + " not found.");
    }


    public boolean addUserOrUpdateConnection(String userId, int deviceId) {
        boolean found = false;
        boolean resp = false;
        for (User user : users) {
            if (user.getUserId().equals(userId) && user.getDeviceId() == deviceId) {
                found = true;
                if (!user.isConectado()) {
                    user.setConectado(true);
                    System.out.println("User " + userId + " with device ID " + deviceId + " connected");
                } else {
                    resp = true;
                    System.out.println("User " + userId + " with device ID " + deviceId + " is already connected");
                }
                break;
            }
        }
        if (!found) {
            users.add(new User(userId, deviceId, "", true));
            System.out.println("New user added: " + userId + " with device ID " + deviceId);
        }
        return resp;
    }


    private static final int BUFFER_SIZE = 4096;
    private static byte[] calculateHash(File file, byte[] nonce) throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
            digest.update(nonce);
        }
        return digest.digest();
    }
    

	
    
    public static void main(String[] args) throws IOException {
        
        System.out.println("servidor: main");
		IoTServer server = new IoTServer();
        int port;
        String pwdCifra;
        String keystore;
        String pwdKeyS;
        if (args.length==4) {
            port = 12345;
            pwdCifra = args[0];
            keystore = args[1];
            pwdKeyS = args[2];
            apiKey = args[3];        
        } else {
            port = Integer.parseInt(args[0]);
            pwdCifra = args[1];
            keystore = args[2];
            pwdKeyS = args[3];
            apiKey = args[4];
        }

        try {

           SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
           
            KeySpec keySpec = new PBEKeySpec(pwdCifra.toCharArray(), SALT, ITERATIONS, KEY_LENGTH);
            SecretKey tmp = keyFactory.generateSecret(keySpec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
           
            // ^ a chave pode ser usada para encriptar ou desencriptar
           
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            

            byte[] keyBytes = secretKey.getEncoded();
           
            System.out.println("Generated SecretKey (Base64): " + java.util.Base64.getEncoder().encodeToString(keyBytes));
           
            } catch (Exception e) {
           
            e.printStackTrace();
           
            }


		try {
            server.startServer(port, pwdKeyS);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void startServer (int port, String pwdKeyS) throws IOException{
		ServerSocket sSoc = null;


        System.setProperty("javax.net.ssl.keyStore", "keystore.server");
        System.setProperty("javax.net.ssl.keyStorePassword", pwdKeyS);
        System.setProperty("javax.net.ssl.keyStoreAlias", "servidor");
        ServerSocketFactory ssf = SSLServerSocketFactory.getDefault( );
        SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(port);


		while(true) {
			try {
				Socket inSoc = ss.accept();
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
 
		@SuppressWarnings("unlikely-arg-type")
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
				}catch (ClassNotFoundException e1) {
					e1.printStackTrace();
                    
				}
                
    
                // 1) Enviar nonce aleatório ao cliente
                long nonce = generateNonce();
                outStream.writeObject(nonce);
                outStream.flush();
                // 2) Receber resposta do cliente (assinatura do nonce)
                byte[] signature = (byte[]) inStream.readObject();
                 
                String c2fa = generateC2FA();
                sendC2FAByEmail(user_id, c2fa, apiKey);
                String userInputC2FA = (String) inStream.readObject();

                if (userInputC2FA.equals(c2fa)) {
                    outStream.writeObject("Autenticação bem-sucedida!");
                    System.out.println("Autenticação bem-sucedida!");
                } else {
                    outStream.writeObject("Autenticação falhada. O código introduzido é inválido.");
                    System.out.println("Autenticação falhada. O código introduzido é inválido.");
                    return;
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

                long nonce2 = generateNonce();
                outStream.writeObject(nonce2);
                outStream.flush();
                byte[] hash = (byte[]) inStream.readObject();
                File device = new File("IoTDevice.java");
                ByteBuffer bffr = ByteBuffer.allocate(Long.BYTES);
                bffr.putLong(nonce2);
                byte[] calchash = calculateHash(device,bffr.array());
                

                String tested;
                if (hash.equals(calchash)) {
                    tested = "NOKTESTED";
                    outStream.writeObject(tested);
                    return;
                }
                tested = "OKTESTED";
                outStream.writeObject(tested);

                outStream.writeObject(addUserOrUpdateConnection(user_id,dev_id));           
                
                
                if (!deviceTemperatures.containsKey(dev_id)) {
                    deviceTemperatures.put(dev_id, null);
                } else {
                    System.out.println("Device with ID " + dev_id + " already exists in the map.");
                }
                

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




                    switch (comandoSplit[0]) {
                        case "CREATE":
                            boolean existe = false;
                            if (comandoSplit.length < 2) {
                                erro = true;
                                outStream.writeObject("falta de parametros");
                            } else {
                                try {
                                    dominios = new File("./dominios.txt");
                                    sc1 = new Scanner(dominios);
                                    while (sc1.hasNextLine()) {
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
                            break;

                        case "ADD":
                            if (comandoSplit.length < 3) {
                                erro = true;
                                outStream.writeObject("falta de parametros");
                            } else {
                                boolean existeD = false;
                                boolean perm = false;
                                boolean existeU = false;
                                boolean done = false;
                                try {
                                    dominios = new File("./dominios.txt");
                                    sc1 = new Scanner(dominios);
                                    while (sc1.hasNextLine()) {
                                        String line = sc1.nextLine();
                                        String[] dSplit = line.split("-");
                                        dContent = dContent.concat(dSplit[0] + "-" + dSplit[1] + "-" + dSplit[2]);
                                        if (dSplit[0].equals(comandoSplit[2])) {
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
                                                    dContent = dContent.concat(comandoSplit[1] + ":-" + dSplit[3] + "\n");
                                                } else
                                                    dContent = dContent.concat("-" + dSplit[3] + "\n");
                                            } else
                                                dContent = dContent.concat("-" + dSplit[3] + "\n");
                                        } else
                                            dContent = dContent.concat("-" + dSplit[3] + "\n");
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
                                            if (done) {
                                                outStream.writeObject("NOK");
                                            } else {
                                                outStream.writeObject("OK");
                                            }
                                        }
                                    }
                                }
                                wr.write(dContent);
                                wr.close();
                            }
                            break;

                        case "RD":
                            if (comandoSplit.length < 2) {
                                erro = true;
                                outStream.writeObject("falta de parametros");
                            } else {
                                boolean existeD = false;
                                boolean perm = false;
                                boolean permAux = false;
                                boolean done = false;
                                try {
                                    dominios = new File("./dominios.txt");
                                    sc1 = new Scanner(dominios);
                                    while (sc1.hasNextLine()) {
                                        permAux = false;
                                        String line = sc1.nextLine();
                                        dContent = dContent.concat(line);
                                        String[] dSplit = line.split("-");
                                        if (dSplit[0].equals(comandoSplit[1])) {
                                            existeD = true;
                                            if (user_id.equals(dSplit[1])) {
                                                permAux = true;
                                                perm = true;
                                            }
                                            String[] usersSpt = dSplit[2].split(":");
                                            int i = 0;
                                            while (!permAux && i < usersSpt.length) {
                                                if (usersSpt[i].equals(user_id)) {
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
                                            dContent = dContent.concat(dev_id + ":\n");
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
                                        if (done) {
                                            outStream.writeObject("NOK");
                                        } else {
                                            outStream.writeObject("OK");
                                        }
                                    }

                                }
                                wr.write(dContent);
                                wr.close();
                            }
                            break;

                        case "ET":
                            if (comandoSplit.length < 2) {
                                erro = true;
                                outStream.writeObject("falta de parametros");
                            } else {
                                try {
                                    float temp = Float.parseFloat(comandoSplit[1]);
                                    deviceTemperatures.put(dev_id, temp);
                                    System.out.println("Temperature updated for device ID " + dev_id + " to " + temp);

                                } catch (Exception e) {
                                    outStream.writeObject("NOK");
                                }
                                outStream.writeObject("OK");
                            }
                            break;

                        case "EI":
                            if (comandoSplit.length < 2) {
                                erro = true;
                                outStream.writeObject("not waiting");
                                outStream.writeObject("falta de parametros");
                            } else {
                                outStream.writeObject("waiting");
                                boolean exists = inStream.readObject().equals("existe");
                                if (exists) {
                                    File img = new File("./ser/" + comandoSplit[1]);
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
                                                bytesRead = inStream.read(buffer, 0, 1024);
                                            } else {
                                                bytesRead = inStream.read(buffer, 0, totalSize);
                                            }
                                            output.write(buffer, 0, bytesRead);
                                            totalSize -= bytesRead;
                                        }
                                        output.close();
                                        fout.close();

                                    } catch (Exception e) {
                                        outStream.writeObject("NOK");
                                    }
                                    output.write(buffer, 0, 1024);
                                    outStream.writeObject("OK");
                                    changeUserImageName(user_id, dev_id, comandoSplit[1]);
                                } else {
                                    outStream.writeObject("NOK");
                                }
                            }
                            break;

                        case "RT":
                            if (comandoSplit.length < 2) {
                                erro = true;
                                outStream.writeObject("not waiting");
                                outStream.writeObject("falta de parametros");
                            } else {
                                boolean existeD = false;
                                boolean perm = false;
                                boolean nodata = true;
                                try {
                                    dominios = new File("./dominios.txt");
                                    sc1 = new Scanner(dominios);
                                    while (sc1.hasNextLine()) {
                                        String line = sc1.nextLine();
                                        String[] dSplit = line.split("-");
                                        if (dSplit[0].equals(comandoSplit[1])) {
                                            existeD = true;

                                            String[] usersSpt = dSplit[2].split(":");
                                            int i = 0;

                                            if (user_id.equals(dSplit[1])) {
                                                perm = true;
                                            }

                                            while (!perm && i < usersSpt.length) {
                                                if (usersSpt[i].equals(user_id)) {
                                                    perm = true;
                                                }
                                                i++;
                                            }

                                            if (perm) {

                                                File tempFile = new File("./ser/temperature_data.txt");
                                                List<String> devices = Arrays.asList(dSplit[3].split(":"));

                                                try (BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile))) {
                                                    // Escrever os dados de temperatura no arquivo de texto
                                                    for (Map.Entry<Integer, Float> entry : deviceTemperatures.entrySet()) {
                                                        if (devices.contains(entry.getKey().toString())) {
                                                            nodata = false;
                                                            writer.write("device: " + entry.getKey() + " -> temperatura: " + entry.getValue() + "\n");
                                                        }

                                                    }
                                                } catch (IOException e) {
                                                    System.err.println("Erro ao escrever no arquivo temporário: " + e.getMessage());

                                                }

                                                // Obter o tamanho do arquivo
                                                long fileSize = tempFile.length();

                                                if (!nodata) {
                                                    outStream.writeObject("waiting");

                                                    FileInputStream fin = new FileInputStream(tempFile);
                                                    InputStream input = new BufferedInputStream(fin);
                                                    outStream.writeObject((long) fileSize);
                                                    byte[] buffer = new byte[1024];
                                                    int bytesRead;
                                                    while ((bytesRead = input.read(buffer)) != -1) {
                                                        outStream.write(buffer, 0, bytesRead);
                                                    }
                                                    input.close();
                                                } else {
                                                    outStream.writeObject("not waiting");
                                                }
                                            } else {
                                                outStream.writeObject("not waiting");
                                            }
                                        }
                                    }
                                    sc1.close();

                                } catch (Exception e) {

                                }

                                if (!existeD) {
                                    outStream.writeObject("NODM");
                                } else {
                                    if (!perm) {
                                        outStream.writeObject("NOPERM");
                                    } else {
                                        if (nodata) {
                                            outStream.writeObject("NODATA");
                                        } else {
                                            outStream.writeObject("OK");
                                        }
                                    }
                                }
                            }
                            break;

                        case "RI":
                            if (comandoSplit.length < 2) {
                                erro = true;
                                outStream.writeObject("not waiting");
                                outStream.writeObject("falta de parametros");
                            } else {
                                boolean existeID = false;
                                boolean perm = false;
                                String[] userDev = comandoSplit[1].split(":");
                                String imgName = "";
                                for (User user : users) {
                                    if (user.getUserId().equals(userDev[0]) && user.getDeviceId() == Integer.parseInt(userDev[1])) {
                                        existeID = true;
                                        imgName = user.getImgName();
                                    }
                                }

                                if (existeID && !imgName.equals("")) {
                                    try {
                                        File img = new File("./ser/" + imgName);
                                        outStream.writeObject("waiting");
                                        outStream.writeObject(imgName);
                                        long fileSize = img.length();
                                        FileInputStream fin = new FileInputStream(img);
                                        InputStream input = new BufferedInputStream(fin);
                                        outStream.writeObject((long) fileSize);
                                        byte[] buffer = new byte[1024];
                                        int bytesRead;
                                        while ((bytesRead = input.read(buffer)) != -1) {
                                            outStream.write(buffer, 0, bytesRead);
                                        }
                                        input.close();

                                    } catch (Exception e) {
                                        outStream.writeObject("not waiting");
                                    }
                                } else {
                                    outStream.writeObject("not waiting");
                                }

                                if (!existeID) {
                                    outStream.writeObject("NOID");
                                } else {
                                    if (imgName.equals("")) {
                                        outStream.writeObject("NODATA");
                                    } else {
                                        outStream.writeObject("OK");
                                    }
                                }

                            }
                            break;

                        case "MYDOMAINS":
                        case "MYDOMAIN":
                            ArrayList<String> dms = devicesDm(dev_id);
                            outStream.writeObject(dms);
                            break;

                        case "exit":
                        case "e":
                            loop = false;
                            System.out.println("User " + user_id + " desconectado");
                            outStream.writeObject("Foi desconectado com sucesso");
                            break;
                    }
                }

				outStream.close();
				inStream.close();
 			
				socket.close();

			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            } 
		}

        private ArrayList<String> devicesDm(int dev_id) { 
            ArrayList<String> dms = new ArrayList<String>();
            try {
                File dominios = new File("dominios.txt");
                Scanner sc1 = new Scanner(dominios);
                    
                while (sc1.hasNextLine()) {
                    String line = sc1.nextLine();
                    String[] dSplit = line.split("-");
                    String[] devicesAdded = dSplit[3].split(":");
                    for (String dev : devicesAdded) {
                        if (dev.equals(Integer.toString(dev_id))) {
                            dms.add(dSplit[0]);
                        }
                    }
                }
                sc1.close();
            } catch (Exception e) {
                // TODO: handle exception
            }
            
            return dms;
        }
	}

}
