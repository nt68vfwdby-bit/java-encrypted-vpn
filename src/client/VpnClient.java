package client;

import crypto.SecureChannel;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VpnClient {
    private final int localSocksPort;
    private final String vpnServerHost;
    private final int vpnServerPort;
    private final String secret;
    private final ExecutorService threadPool = Executors.newCachedThreadPool();

    public VpnClient(int localSocksPort, String vpnServerHost, int vpnServerPort, String secret) {
        this.localSocksPort = localSocksPort;
        this.vpnServerHost = vpnServerHost;
        this.vpnServerPort = vpnServerPort;
        this.secret = secret;
    }

    public void start() throws IOException {
        try (ServerSocket localServer = new ServerSocket(localSocksPort, 50, InetAddress.getByName("127.0.0.1"))) {
            System.out.println("Локальный VPN-клиент (SOCKS5) запущен на 127.0.0.1:" + localSocksPort);
            System.out.println("Трафик шифруется (ECDH + AES-256-GCM) -> " + vpnServerHost + ":" + vpnServerPort);

            while (true) {
                Socket appSocket = localServer.accept();
                threadPool.submit(() -> handleLocalApp(appSocket));
            }
        }
    }

    private void handleLocalApp(Socket appSocket) {
        try (
            Socket local = appSocket;
            DataInputStream appIn = new DataInputStream(new BufferedInputStream(local.getInputStream()));
            DataOutputStream appOut = new DataOutputStream(new BufferedOutputStream(local.getOutputStream()))
        ) {
            int version = appIn.readUnsignedByte();
            if (version != 5) return;

            int nMethods = appIn.readUnsignedByte();
            byte[] methods = new byte[nMethods];
            appIn.readFully(methods);

            appOut.write(new byte[]{0x05, 0x00});
            appOut.flush();

            appIn.readUnsignedByte();
            int cmd = appIn.readUnsignedByte();
            appIn.readUnsignedByte();
            int addrType = appIn.readUnsignedByte();

            if (cmd != 1) return;

            String targetHost;
            if (addrType == 1) {
                byte[] ip = new byte[4];
                appIn.readFully(ip);
                targetHost = InetAddress.getByAddress(ip).getHostAddress();
            } else if (addrType == 3) {
                int domainLen = appIn.readUnsignedByte();
                byte[] domainBytes = new byte[domainLen];
                appIn.readFully(domainBytes);
                targetHost = new String(domainBytes, StandardCharsets.UTF_8);
            } else {
                return;
            }

            int targetPort = appIn.readUnsignedShort();

            try (
                Socket vpnSocket = new Socket(vpnServerHost, vpnServerPort);
                DataInputStream vpnIn = new DataInputStream(new BufferedInputStream(vpnSocket.getInputStream()));
                DataOutputStream vpnOut = new DataOutputStream(new BufferedOutputStream(vpnSocket.getOutputStream()))
            ) {
                SecureChannel channel = SecureChannel.performHandshake(vpnIn, vpnOut, secret);

                String target = targetHost + ":" + targetPort;
                channel.sendEncrypted(vpnOut, target.getBytes(StandardCharsets.UTF_8));

                appOut.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
                appOut.flush();

                System.out.println("Защищённый запрос -> " + target);

                Thread serverToApp = new Thread(() -> {
                    try {
                        while (true) {
                            byte[] plainResponse = channel.receiveEncrypted(vpnIn);
                            appOut.write(plainResponse);
                            appOut.flush();
                        }
                    } catch (Exception ignored) {
                    } finally {
                        closeQuietly(local);
                    }
                });

                serverToApp.start();

                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = appIn.read(buffer)) != -1) {
                    byte[] chunk = new byte[bytesRead];
                    System.arraycopy(buffer, 0, chunk, 0, bytesRead);
                    channel.sendEncrypted(vpnOut, chunk);
                }
            }
        } catch (Exception e) {
            System.err.println("Ошибка клиента: " + e.getMessage());
        }
    }

    private void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    public static void main(String[] args) throws IOException {
        int localPort = args.length > 0 ? Integer.parseInt(args[0]) : 1085;
        String serverHost = args.length > 1 ? args[1] : "127.0.0.1";
        int serverPort = args.length > 2 ? Integer.parseInt(args[2]) : 9090;
        String secret = args.length > 3 ? args[3] : "SuperSecretVpnKey2026!";

        new VpnClient(localPort, serverHost, serverPort, secret).start();
    }
}
