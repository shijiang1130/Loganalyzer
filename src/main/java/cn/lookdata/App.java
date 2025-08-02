package cn.lookdata;

import java.io.*;
import java.util.regex.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.Locale;
import java.util.*;
import com.jcraft.jsch.JSchException;
import cn.lookdata.SSHUtils;
import cn.lookdata.Download;
public class App {
    // OWASP相关的攻击模式
    private static final Pattern OWASP_ATTACK_PATTERNS = Pattern.compile(
        "(sql[\\s\\S]*?injection|xss|rce|directory[\\s\\S]*?traversal|command[\\s\\S]*?injection|file[\\s\\S]*?inclusion|csrf|broken[\\s\\S]*?authentication|sensitive[\\s\\S]*?data|xml[\\s\\S]*?external|insecure[\\s\\S]*?deserialization|using[\\s\\S]*?components|insufficient[\\s\\S]*?logging)",
        Pattern.CASE_INSENSITIVE
    );

    // 其他攻击模式
    private static final Pattern OTHER_ATTACK_PATTERNS = Pattern.compile(
        "(password[\\s\\S]*?(brute|force|暴力)|0day|exploit|非法[\\s\\S]*?访问|恶意[\\s\\S]*?请求|扫描[\\s\\S]*?攻击|(admin|login|wp-login)[\\s\\S]*?(attempt|try)|(denial[\\s\\S]*?service|ddos))",
        Pattern.CASE_INSENSITIVE
    );

    // 敏感路径模式
    private static final Pattern SENSITIVE_PATH_PATTERNS = Pattern.compile(
        "(\\/.aws\\/credentials|\\/.env|\\/.git\\/config|\\/server-status|\\/actuator|\\/debug|\\/wp-config\\.php|\\/database\\.sqlite)",
        Pattern.CASE_INSENSITIVE
    );

    // 异常请求模式（空User-Agent和异常状态码）
    private static final Pattern ANOMALOUS_REQUEST_PATTERNS = Pattern.compile("\\\"-\\\" \\\\s \\\"-\\\" \\\\s \\\"-\\\" \\\\s \\\"-\\\" \\\\s .* \\\" (400|403|404|418) ",
        Pattern.CASE_INSENSITIVE
    );

    // 正常访问记录模式（418状态码表示国外IP地址）
    private static final Pattern NORMAL_ACCESS_PATTERNS = Pattern.compile(
        ".* \\\"GET / HTTP/1\\.1\\\" 418 .* \\\"Mozilla/.*\\\"",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern ATTACK_PATTERNS = Pattern.compile(
        "(password[\\s\\S]*?(brute|force|暴力)|0day|exploit|sql[\\s\\S]*?injection|xss|rce|directory[\\s\\S]*?traversal|非法[\\s\\S]*?访问|恶意[\\s\\S]*?请求|扫描[\\s\\S]*?攻击|(admin|login|wp-login)[\\s\\S]*?(attempt|try)|(cmd|command)[\\s\\S]*?exec|(file|path)[\\s\\S]*?inclusion|(cross[\\s\\S]*?site|csrf)|(remote[\\s\\S]*?code)|(denial[\\s\\S]*?service|ddos)|thinkphp[\\s\\S]*?rce|\\\\x03\\\\x00\\\\x00/\\\\*\\\\xE0\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00.*?mstshash=Administr|exec\\s*\\(.*\\)|system\\s*\\(.*\\)|eval\\s*\\(.*\\)|assert\\s*\\(.*\\)|\\$\\{.*\\}|\\\\x[0-9a-fA-F]{2})",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SEARCH_ENGINE_PATTERNS = Pattern.compile(
        "(google[\\s\\S]*?bot|bing[\\s\\S]*?bot|yandex|baidu[\\s\\S]*?spider|duckduck[\\s\\S]*?bot|sogou|exa[\\s\\S]*?bot|face[\\s\\S]*?bot|ia[\\s\\S]*?archiver|msn[\\s\\S]*?bot|slurp|teoma|ahrefs|mj12[\\s\\S]*?bot|petal[\\s\\S]*?bot|apple[\\s\\S]*?bot|semrush[\\s\\S]*?bot)",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern URL_PATTERN = Pattern.compile("(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\s(\\S+)\\sHTTP");
    private static final Pattern RESPONSE_CODE_PATTERN = Pattern.compile("\\\" (4\\d{2}) ");

    public static void main(String[] args) {
        // 检查参数是否足够
        if (args.length < 5) {
            System.out.println("使用方法: java -cp target/classes cn.lookdata.App <hostname> <username> <password> <remoteLogPath> <localDir> [port]");
            System.out.println("参数说明:");
            System.out.println("  <hostname>: SSH服务器地址");
            System.out.println("  <username>: SSH用户名");
            System.out.println("  <password>: SSH密码");
            System.out.println("  <remoteLogPath>: 远程日志文件路径");
            System.out.println("  <localDir>: 本地保存目录");
            System.out.println("  [port]: SSH端口(可选，默认22)");
            return;
        }

        // 远程SSH服务器信息
        String hostname = args[0];
        String username = args[1];
        String password = args[2];
        int port = 22; // 默认SSH端口
        String remoteLogPath = args[3];
        String localDir = args[4];

        // 如果提供了端口参数，则使用该端口
        if (args.length > 5) {
            try {
                port = Integer.parseInt(args[5]);
                System.out.println("使用自定义SSH端口: " + port);
            } catch (NumberFormatException e) {
                System.out.println("无效的端口号，使用默认端口22");
            }
        }

        LocalDate today = LocalDate.now();
        new File(localDir).mkdirs();

        System.out.println("连接到SSH服务器: " + hostname + ":" + port + "");
        System.out.println("用户名: " + username);
        System.out.println("远程日志路径: " + remoteLogPath);
        System.out.println("本地保存目录: " + localDir);

        try {
            // 从远程SSH服务器读取日志文件内容
            System.out.println("正在从远程服务器读取日志文件: " + remoteLogPath);
            String logContent = SSHUtils.readFileFromSSH(hostname, username, password, port, remoteLogPath);

            // 将远程日志内容保存到本地临时文件
            String localLogPath = localDir + File.separator + "remote_log.log";
            try (PrintWriter writer = new PrintWriter(new FileWriter(localLogPath))) {
                writer.print(logContent);
            }
            System.out.println("日志文件已保存到本地: " + localLogPath);

            // 分析最近3天的日志
            LocalDate threeDaysAgo = today.minusDays(3);
            System.out.println("正在分析从 " + threeDaysAgo + " 到 " + today + " 的日志...");
            FileAnalysisResult result = analyzeLogFileForReport(localLogPath, threeDaysAgo, today);

            // 生成分析报告
            generateReportFromRemoteLog(localDir, today, result);

        } catch (JSchException | IOException e) {
            System.err.println("处理远程日志时出错: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 从远程日志生成报告
     */
    private static void generateReportFromRemoteLog(String localDir, LocalDate today, FileAnalysisResult result) {
        StringBuilder summary = new StringBuilder();
        StringBuilder details = new StringBuilder();
        int totalFiles = 1;
        int totalLines = result.lineCount;
        int totalSuspicious = result.suspiciousCount;
        int totalSearchEngine = (int)result.entries.stream().filter(e -> e.type.equals("SEARCH_ENGINE")).count();
        int totalNormal = totalLines - totalSuspicious - totalSearchEngine;

        Map<String, Map<String, Integer>> attackStats = new HashMap<>();
        Map<String, Map<String, Integer>> searchEngineStats = new HashMap<>();
        Map<String, Integer> normalUrlStats = new HashMap<>();

        for (LogEntry entry : result.entries) {
            if (entry.type.equals("ATTACK") || entry.type.equals("SENSITIVE_PATH_ACCESS") || entry.type.equals("ANOMALOUS_REQUEST")) {
                attackStats.computeIfAbsent(entry.type, k -> new HashMap<>())
                        .merge(entry.ip, 1, Integer::sum);
            } else if (entry.type.equals("SEARCH_ENGINE")) {
                searchEngineStats.computeIfAbsent(entry.type, k -> new HashMap<>())
                        .merge(entry.ip, 1, Integer::sum);
            }
        }

        // 统计正常访问的URL
        details.append("<h3>remote_log.log</h3>");
        if (result.entries.isEmpty()) {
            details.append("<div>No suspicious activities found</div>");
        } else {
            for (LogEntry entry : result.entries) {
                String cssClass = entry.type.equals("ATTACK") ? "attack" : "search-engine";
                details.append(String.format("<div class='%s'>" +
                                "<strong>[%s]</strong> %s<br>" +
                                "<small>IP: %s</small>" +
                                "</div>",
                        cssClass, entry.type, entry.message, entry.ip));
            }
        }

        summary.append("<h3>Attack Activities</h3>");
        summary.append("<table><tr><th>Attack Type</th><th>IP Address</th><th>Count</th></tr>");
        for (Map.Entry<String, Map<String, Integer>> typeEntry : attackStats.entrySet()) {
            for (Map.Entry<String, Integer> ipEntry : typeEntry.getValue().entrySet()) {
                String rowId = "attack-" + typeEntry.getKey().replaceAll("[^a-zA-Z0-9]", "") + "-" + ipEntry.getKey().replaceAll("[^a-zA-Z0-9]", "");
                summary.append(String.format("<tr onclick='scrollToDetails(\"%s\")' style='cursor: pointer;'><td>%s</td><td>%s</td><td>%d</td></tr>",
                        rowId, typeEntry.getKey(), ipEntry.getKey(), ipEntry.getValue()));
            }
        }
        summary.append("</table>");

        summary.append("<h3>Search Engine Activities</h3>");
        summary.append("<table><tr><th>Type</th><th>IP Address</th><th>Count</th></tr>");
        for (Map.Entry<String, Map<String, Integer>> typeEntry : searchEngineStats.entrySet()) {
            for (Map.Entry<String, Integer> ipEntry : typeEntry.getValue().entrySet()) {
                String rowId = "search-" + typeEntry.getKey().replaceAll("[^a-zA-Z0-9]", "") + "-" + ipEntry.getKey().replaceAll("[^a-zA-Z0-9]", "");
                summary.append(String.format("<tr onclick='scrollToDetails(\"%s\")' style='cursor: pointer;'><td>%s</td><td>%s</td><td>%d</td></tr>",
                        rowId, typeEntry.getKey(), ipEntry.getKey(), ipEntry.getValue()));
            }
        }
        summary.append("</table>");

        // 添加正常访问URL统计表格
        summary.append("<h3>Normal Access URLs</h3>");
        summary.append("<table><tr><th>URL</th><th>Access Count</th></tr>");
        
        // 分析所有日志行，排除攻击、敏感路径和异常请求
        Map<String, Integer> urlAccessCount = analyzeNormalAccessUrls(result.allLines);
        for (Map.Entry<String, Integer> urlEntry : urlAccessCount.entrySet()) {
            String rowId = "url-" + urlEntry.getKey().replaceAll("[^a-zA-Z0-9]", "").substring(0, Math.min(20, urlEntry.getKey().replaceAll("[^a-zA-Z0-9]", "").length()));
            summary.append(String.format("<tr onclick='scrollToDetails(\"%s\")' style='cursor: pointer;'><td>%s</td><td>%d</td></tr>",
                    rowId, urlEntry.getKey(), urlEntry.getValue()));
        }
        summary.append("</table>");

        // 添加40x响应代码统计表格
        summary.append("<h3>40x Response Codes</h3>");
        summary.append("<table><tr><th>Response Code</th><th>Count</th></tr>");
        
        // 分析所有日志行中的40x响应代码
        Map<String, Integer> responseCodeCount = analyzeResponseCodes(result.allLines);
        for (Map.Entry<String, Integer> codeEntry : responseCodeCount.entrySet()) {
            String rowId = "code-" + codeEntry.getKey();
            summary.append(String.format("<tr onclick='scrollToDetails(\"%s\")' style='cursor: pointer;'><td>%s</td><td>%d</td></tr>",
                    rowId, codeEntry.getKey(), codeEntry.getValue()));
        }
        summary.append("</table>");

        String escapedSummary = summary.toString().replace("%", "%%");
        String escapedDetails = details.toString().replace("%", "%%");

        // 假设Download类存在并提供generateReportFile方法
        // 如果不存在，这里会抛出异常，需要根据实际情况修改
        try {
            Download.generateReportFile(localDir, today.toString(), totalFiles, totalLines, 
                    totalSuspicious, totalSearchEngine, escapedSummary, escapedDetails);
            System.out.println("报告已生成: " + localDir + File.separator + "report.html");
        } catch (Exception e) {
            System.err.println("生成报告时出错: " + e.getMessage());
            // 输出异常堆栈信息
            e.printStackTrace();
            // 简单输出结果到控制台
            System.out.println("\n===== 异常IP地址 =====");
            for (Map.Entry<String, Map<String, Integer>> typeEntry : attackStats.entrySet()) {
                for (Map.Entry<String, Integer> ipEntry : typeEntry.getValue().entrySet()) {
                    System.out.println(ipEntry.getKey() + " (" + ipEntry.getValue() + " 次攻击)");
                }
            }
        }
    }

    /**
     * 生成HTML报告（原方法）
     */
    private static void generateHtmlReport(String localDir, LocalDate today) {
        StringBuilder summary = new StringBuilder();
        StringBuilder details = new StringBuilder();
        int totalFiles = 0;
        int totalLines = 0;
        int totalSuspicious = 0;
        int totalSearchEngine = 0;
        
        File[] logFiles = new File(localDir).listFiles((dir, name) -> name.endsWith(".log"));
        if (logFiles != null && logFiles.length > 0) {
            totalFiles = logFiles.length;
            
            Map<String, Map<String, Integer>> attackStats = new HashMap<>();
            Map<String, Map<String, Integer>> searchEngineStats = new HashMap<>();
            
            for (File logFile : logFiles) {
                System.out.println("Processing file: " + logFile.getName());
                FileAnalysisResult result = analyzeLogFileForReport(logFile.getAbsolutePath(), today);
                totalLines += result.lineCount;
                totalSuspicious += result.suspiciousCount;
                totalSearchEngine += (int)result.entries.stream().filter(e -> e.type.equals("SEARCH_ENGINE")).count();

                for (LogEntry entry : result.entries) {
                    if (entry.type.equals("ATTACK") || entry.type.equals("SENSITIVE_PATH_ACCESS") || entry.type.equals("ANOMALOUS_REQUEST")) {
                        attackStats.computeIfAbsent(entry.type, k -> new HashMap<>())
                                  .merge(entry.ip, 1, Integer::sum);
                    } else if (entry.type.equals("SEARCH_ENGINE")) {
                        searchEngineStats.computeIfAbsent(entry.type, k -> new HashMap<>())
                                        .merge(entry.ip, 1, Integer::sum);
                    }
                }

                details.append(String.format("<h3>%s</h3>", logFile.getName()));
                if (result.entries.isEmpty()) {
                    details.append("<div>No suspicious activities found</div>");
                } else {
                    for (LogEntry entry : result.entries) {
                        String cssClass = entry.type.equals("ATTACK") ? "attack" : "search-engine";
                        details.append(String.format("<div class='%s'>" +
                            "<strong>[%s]</strong> %s<br>" +
                            "<small>IP: %s</small>" +
                            "</div>",
                            cssClass, entry.type, entry.message, entry.ip));
                    }
                }
            }

            summary.append("<h3>Attack Activities</h3>");
            summary.append("<table><tr><th>Attack Type</th><th>IP Address</th><th>Count</th></tr>");
            for (Map.Entry<String, Map<String, Integer>> typeEntry : attackStats.entrySet()) {
                for (Map.Entry<String, Integer> ipEntry : typeEntry.getValue().entrySet()) {
                    summary.append(String.format("<tr><td>%s</td><td>%s</td><td>%d</td></tr>",
                        typeEntry.getKey(), ipEntry.getKey(), ipEntry.getValue()));
                }
            }
            summary.append("</table>");

            summary.append("<h3>Search Engine Activities</h3>");
            summary.append("<table><tr><th>Type</th><th>IP Address</th><th>Count</th></tr>");
            for (Map.Entry<String, Map<String, Integer>> typeEntry : searchEngineStats.entrySet()) {
                for (Map.Entry<String, Integer> ipEntry : typeEntry.getValue().entrySet()) {
                    summary.append(String.format("<tr><td>%s</td><td>%s</td><td>%d</td></tr>",
                        typeEntry.getKey(), ipEntry.getKey(), ipEntry.getValue()));
                }
            }
            summary.append("</table>");
        } else {
            System.out.println("No log files found in directory: " + localDir);
            summary.append("<div>No log files found</div>");
            details.append("<div>No log files were found in the specified directory</div>");
        }
        
        String escapedSummary = summary.toString().replace("%", "%%");
        String escapedDetails = details.toString().replace("%", "%%");
        
        try {
            Download.generateReportFile(localDir, today.toString(), totalFiles, totalLines, 
                totalSuspicious, totalSearchEngine, escapedSummary, escapedDetails);
        } catch (IOException e) {
            System.err.println("生成报告时出错: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static FileAnalysisResult analyzeLogFileForReport(String filePath, LocalDate startDate, LocalDate endDate) {
        FileAnalysisResult result = new FileAnalysisResult();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 提取日志中的日期
                LocalDate logDate = extractDateFromLog(line);
                if (logDate != null && !logDate.isBefore(startDate) && !logDate.isAfter(endDate)) {
                    result.lineCount++;
                    result.allLines.add(line); // 添加所有符合条件的行到allLines
                    LogEntry entry = analyzeLogLine(line);
                    if (entry != null) {
                        result.entries.add(entry);
                        if (entry.type.equals("ATTACK") || entry.type.equals("SENSITIVE_PATH_ACCESS") || entry.type.equals("ANOMALOUS_REQUEST")) {
                            result.suspiciousCount++;
                        }
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Error analyzing file " + filePath + ": " + e.getMessage());
        }
        return result;
    }

    private static FileAnalysisResult analyzeLogFileForReport(String filePath, LocalDate today) {
        // 默认分析当天的日志
        return analyzeLogFileForReport(filePath, today, today);
    }

    private static LocalDate extractDateFromLog(String line) {
        // 匹配日志中的日期格式：01/Aug/2025:03:20:33 +0800
        Pattern datePattern = Pattern.compile("(\\d{2})/(\\w{3})/(\\d{4})");
        Matcher matcher = datePattern.matcher(line);
        if (matcher.find()) {
            try {
                String day = matcher.group(1);
                String month = matcher.group(2);
                String year = matcher.group(3);
                // 将月份缩写转换为数字
                DateTimeFormatter formatter = new DateTimeFormatterBuilder()
                    .parseCaseInsensitive()
                    .appendPattern("dd/MMM/yyyy")
                    .toFormatter(Locale.ENGLISH);
                return LocalDate.parse(day + "/" + month + "/" + year, formatter);
            } catch (Exception e) {
                // 日期解析失败
                System.out.println("日期解析失败: " + e.getMessage() + " 行: " + line);
                return null;
            }
        }
        return null;
    }

    private static LogEntry analyzeLogLine(String line) {
        Matcher owaspMatcher = OWASP_ATTACK_PATTERNS.matcher(line);
        Matcher attackMatcher = ATTACK_PATTERNS.matcher(line);
        Matcher sensitivePathMatcher = SENSITIVE_PATH_PATTERNS.matcher(line);
        Matcher anomalousRequestMatcher = ANOMALOUS_REQUEST_PATTERNS.matcher(line);
        Matcher searchEngineMatcher = SEARCH_ENGINE_PATTERNS.matcher(line);
        
        if (owaspMatcher.find()) {
            String ip = extractIP(line);
            return new LogEntry("OWASP_ATTACK", line, ip != null ? ip : "Unknown");
        } else if (attackMatcher.find()) {
            String ip = extractIP(line);
            return new LogEntry("ATTACK", line, ip != null ? ip : "Unknown");
        } else if (sensitivePathMatcher.find()) {
            String ip = extractIP(line);
            return new LogEntry("SENSITIVE_PATH_ACCESS", line, ip != null ? ip : "Unknown");
        } else if (anomalousRequestMatcher.find()) {
            String ip = extractIP(line);
            return new LogEntry("ANOMALOUS_REQUEST", line, ip != null ? ip : "Unknown");
        } else if (searchEngineMatcher.find()) {
            String ip = extractIP(line);
            return new LogEntry("SEARCH_ENGINE", line, ip != null ? ip : "Unknown");
        }
        return null;
    }

    private static class FileAnalysisResult {
        int lineCount = 0;
        int suspiciousCount = 0;
        List<LogEntry> entries = new ArrayList<>();
        List<String> allLines = new ArrayList<>(); // Added for normal access URL analysis
    }

    private static class LogEntry {
        String type;
        String message;
        String ip;

        LogEntry(String type, String message, String ip) {
            this.type = type;
            this.message = message;
            this.ip = ip;
        }
    }

    private static String extractIP(String line) {
        Matcher ipMatcher = Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b").matcher(line);
        return ipMatcher.find() ? ipMatcher.group() : null;
    }

    // New method to analyze normal access URLs
    private static Map<String, Integer> analyzeNormalAccessUrls(List<String> allLines) {
        Map<String, Integer> urlAccessCount = new HashMap<>();
        for (String line : allLines) {
            // 检查这行是否已经被归类为攻击或搜索引擎活动
            LogEntry entry = analyzeLogLine(line);
            if (entry != null && (entry.type.equals("ATTACK") || entry.type.equals("SENSITIVE_PATH_ACCESS") || 
                                 entry.type.equals("ANOMALOUS_REQUEST") || entry.type.equals("SEARCH_ENGINE"))) {
                // 跳过已经被归类为攻击或搜索引擎活动的行
                continue;
            }
            
            // 只统计正常访问的URL
            Matcher urlMatcher = URL_PATTERN.matcher(line);
            if (urlMatcher.find()) {
                String url = urlMatcher.group(2);
                urlAccessCount.merge(url, 1, Integer::sum);
            }
        }
        return urlAccessCount;
    }

    // New method to analyze response codes
    private static Map<String, Integer> analyzeResponseCodes(List<String> allLines) {
        Map<String, Integer> responseCodeCount = new HashMap<>();
        for (String line : allLines) {
            Matcher responseCodeMatcher = RESPONSE_CODE_PATTERN.matcher(line);
            if (responseCodeMatcher.find()) {
                String code = responseCodeMatcher.group(1);
                responseCodeCount.merge(code, 1, Integer::sum);
            }
        }
        return responseCodeCount;
    }
}
