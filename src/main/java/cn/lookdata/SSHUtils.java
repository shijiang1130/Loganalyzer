package cn.lookdata;

import com.jcraft.jsch.*;
import java.io.*;
import java.util.Properties;

public class SSHUtils {
    private static final int DEFAULT_PORT = 22;

    /**
     * 连接到远程SSH服务器并下载文件
     * @param hostname 主机名
     * @param username 用户名
     * @param password 密码
     * @param remoteFilePath 远程文件路径
     * @param localFilePath 本地保存路径
     * @throws JSchException SSH连接异常
     * @throws IOException IO异常
     */
    public static void downloadFileFromSSH(String hostname, String username, String password, 
                                          String remoteFilePath, String localFilePath) 
                                          throws JSchException, IOException, com.jcraft.jsch.SftpException {
        downloadFileFromSSH(hostname, username, password, DEFAULT_PORT, remoteFilePath, localFilePath);
    }

    /**
     * 连接到远程SSH服务器并下载文件（支持自定义端口）
     * @param hostname 主机名
     * @param username 用户名
     * @param password 密码
     * @param port SSH端口
     * @param remoteFilePath 远程文件路径
     * @param localFilePath 本地保存路径
     * @throws JSchException SSH连接异常
     * @throws IOException IO异常
     */
    public static void downloadFileFromSSH(String hostname, String username, String password, int port, 
                                          String remoteFilePath, String localFilePath) 
                                          throws JSchException, IOException, com.jcraft.jsch.SftpException {
        JSch jsch = new JSch();
        Session session = null;
        ChannelSftp channelSftp = null;

        try {
            // 创建SSH会话
            session = jsch.getSession(username, hostname, port);
            session.setPassword(password);

            // 配置会话属性
            Properties config = new Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            // 连接会话
            session.connect();

            // 打开SFTP通道
            channelSftp = (ChannelSftp) session.openChannel("sftp");
            channelSftp.connect();

            try {
                // 下载文件
                channelSftp.get(remoteFilePath, localFilePath);
            } catch (com.jcraft.jsch.SftpException e) {
                System.err.println("SFTP下载异常: " + e.getMessage());
                throw e; // 重新抛出异常让调用者处理
            }

            System.out.println("文件下载成功: " + remoteFilePath + " -> " + localFilePath);

        } finally {
            // 关闭通道和会话
            if (channelSftp != null && channelSftp.isConnected()) {
                channelSftp.disconnect();
            }
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }
    }

    /**
     * 连接到远程SSH服务器并读取文件内容
     * @param hostname 主机名
     * @param username 用户名
     * @param password 密码
     * @param remoteFilePath 远程文件路径
     * @return 文件内容
     * @throws JSchException SSH连接异常
     * @throws IOException IO异常
     */
    public static String readFileFromSSH(String hostname, String username, String password, 
                                        String remoteFilePath) 
                                        throws JSchException, IOException {
        return readFileFromSSH(hostname, username, password, DEFAULT_PORT, remoteFilePath);
    }

    /**
     * 连接到远程SSH服务器并读取文件内容（支持自定义端口）
     * @param hostname 主机名
     * @param username 用户名
     * @param password 密码
     * @param port SSH端口
     * @param remoteFilePath 远程文件路径
     * @return 文件内容
     * @throws JSchException SSH连接异常
     * @throws IOException IO异常
     */
    public static String readFileFromSSH(String hostname, String username, String password, int port, 
                                        String remoteFilePath) 
                                        throws JSchException, IOException {
        JSch jsch = new JSch();
        Session session = null;
        ChannelExec channelExec = null;
        StringBuilder content = new StringBuilder();

        try {
            // 创建SSH会话
            session = jsch.getSession(username, hostname, port);
            session.setPassword(password);

            // 配置会话属性
            Properties config = new Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            // 连接会话
            session.connect();

            // 打开执行通道
            channelExec = (ChannelExec) session.openChannel("exec");
            // 执行cat命令读取文件
            channelExec.setCommand("cat " + remoteFilePath);

            // 获取命令输出
            InputStream in = channelExec.getInputStream();
            channelExec.connect();

            // 读取输出内容
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }

        } finally {
            // 关闭通道和会话
            if (channelExec != null && channelExec.isConnected()) {
                channelExec.disconnect();
            }
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }

        return content.toString();
    }

    /**
     * 连接到远程SSH服务器并执行命令
     * @param hostname 主机名
     * @param username 用户名
     * @param password 密码
     * @param command 要执行的命令
     * @return 命令输出
     * @throws JSchException SSH连接异常
     * @throws IOException IO异常
     */
    public static String executeCommand(String hostname, String username, String password, 
                                      String command) 
                                      throws JSchException, IOException {
        return executeCommand(hostname, username, password, DEFAULT_PORT, command);
    }

    /**
     * 连接到远程SSH服务器并执行命令（支持自定义端口）
     * @param hostname 主机名
     * @param username 用户名
     * @param password 密码
     * @param port SSH端口
     * @param command 要执行的命令
     * @return 命令输出
     * @throws JSchException SSH连接异常
     * @throws IOException IO异常
     */
    public static String executeCommand(String hostname, String username, String password, int port, 
                                      String command) 
                                      throws JSchException, IOException {
        JSch jsch = new JSch();
        Session session = null;
        ChannelExec channelExec = null;
        StringBuilder output = new StringBuilder();

        try {
            // 创建SSH会话
            session = jsch.getSession(username, hostname, port);
            session.setPassword(password);

            // 配置会话属性
            Properties config = new Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            // 连接会话
            session.connect();

            // 打开执行通道
            channelExec = (ChannelExec) session.openChannel("exec");
            channelExec.setCommand(command);

            // 获取命令输出
            InputStream in = channelExec.getInputStream();
            channelExec.connect();

            // 读取输出内容
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

        } finally {
            // 关闭通道和会话
            if (channelExec != null && channelExec.isConnected()) {
                channelExec.disconnect();
            }
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }

        return output.toString();
    }
}