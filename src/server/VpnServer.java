package server;

import crypto.SecureChannel;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VpnServer {
    private final int port;
    private final String secret;
    private final ExecutorService threadPool = Executors.newCachedThreadPool();

    public VpnServer(int port, String secret) {
        this.port = port;
        this.secret = secret;
    }

    public void start() throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("VPN-сервер запущен на порту " + port);
            System.out.println("Ожидание зашифрованных подключений...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                threadPool.submit(() -> handleClient(clientSocket));
            }
        }
    }

    private void handleClient(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();
        try (
            Socket s = clientSocket;
            DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()))
        ) {
            SecureChannel channel = SecureChannel.performHandshake(in, out, secret);

            byte[] targetBytes = channel.receiveEncrypted(in);
            String target = new String(targetBytes, StandardCharsets.UTF_8);
            int colonIdx = target.lastIndexOf(':');
            String targetHost = target.substring(0, colonIdx);
            int targetPort = Integer.parseInt(target.substring(colonIdx + 1));

            System.out.println("[" + clientIp + "] Туннель -> " + targetHost + ":" + targetPort);

            try (Socket targetSocket = new Socket(targetHost, targetPort)) {
                InputStream targetIn = targetSocket.getInputStream();
                OutputStream targetOut = targetSocket.getOutputStream();

                Thread clientToTarget = new Thread(() -> {
                    try {
                        while (true) {
                            byte[] plainData = channel.receiveEncrypted(in);
                            targetOut.write(plainData);
                            targetOut.flush();
                        }
                    } catch (Exception ignored) {
                    } finally {
                        closeQuietly(targetSocket);
                    }
                });

                clientToTarget.start();

                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = targetIn.read(buffer)) != -1) {
                    byte[] chunk = new byte[bytesRead];
                    System.arraycopy(buffer, 0, chunk, 0, bytesRead);
                    channel.sendEncrypted(out, chunk);
                }
            }
        } catch (SecurityException se) {
            System.err.println("БЛОКИРОВКА БЕЗОПАСНОСТИ [" + clientIp + "]: " + se.getMessage());
        } catch (Exception e) {
            System.err.println("Ошибка соединения: " + e.getMessage());
        }
    }

    private void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9090;
        String secret = args.length > 1 ? args[1] : "SuperSecretVpnKey2026!";
        new VpnServer(port, secret).start();
    }
}
