package cn.lookdata;
import java.io.*;
import java.nio.file.*;

public class Download {
    /**
     * 生成日志分析报告文件
     * @param localDir 本地目录
     * @param date 日期字符串
     * @param totalFiles 总文件数
     * @param totalLines 总行数
     * @param totalSuspicious 总可疑活动数
     * @param totalSearchEngine 总搜索引擎活动数
     * @param summary 摘要内容
     * @param details 详细内容
     * @throws IOException IO异常
     */
    public static void generateReportFile(String localDir, String date, int totalFiles, int totalLines, 
                                         int totalSuspicious, int totalSearchEngine, 
                                         String summary, String details) throws IOException {
        // 创建报告文件路径
        String reportPath = localDir + File.separator + "report.html";
        Path reportFilePath = Paths.get(reportPath);

        // 确保目录存在
        Files.createDirectories(reportFilePath.getParent());

        // 写入报告内容
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportPath))) {
            writer.println("<!DOCTYPE html>");
            writer.println("<html>");
            writer.println("<head>");
            writer.println("    <title>Log Analysis Report</title>");
            writer.println("    <style>");
            writer.println("        body { font-family: Arial, sans-serif; margin: 20px; }");
            writer.println("        h1 { color: #2c3e50; }");
            writer.println("        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }");
            writer.println("        table { width: 100%; border-collapse: collapse; margin-top: 10px; }");
            writer.println("        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }");
            writer.println("        th { background-color: #f2f2f2; }");
            writer.println("        .attack { background-color: #ffdddd; padding: 5px; margin: 2px 0; border-left: 4px solid #ff5252; }");
            writer.println("        .search-engine { background-color: #e3f2fd; padding: 5px; margin: 2px 0; border-left: 4px solid #2196f3; }");
            writer.println("        .stats { margin-top: 20px; }");
            writer.println("        .stat-item { display: inline-block; margin-right: 20px; }");
            writer.println("        .critical { color: #d32f2f; font-weight: bold; }");
            writer.println("        .warning { color: #ff9800; }");
            writer.println("        .info { color: #1976d2; }");
            writer.println("    </style>");
            writer.println("</head>");
            writer.println("<body>");
            writer.println("    <h1>Log Analysis Report - " + date + "</h1>");
            writer.println("    <div class='summary'>");
            writer.println("        <h2>Summary</h2>");
            writer.println("        <div class='overall-stats'>");
            writer.println("            <div>Total Files Analyzed: <span class='stat-item'>" + totalFiles + "</span></div>");
            writer.println("            <div>Total Lines Processed: <span class='stat-item'>" + totalLines + "</span></div>");
            writer.println("            <div>Total Suspicious Activities: <span class='stat-item critical'>" + totalSuspicious + "</span></div>");
            writer.println("            <div>Total Search Engine Activities: <span class='stat-item info'>" + totalSearchEngine + "</span></div>");
            writer.println("        </div>");
            writer.println("        " + summary);
            writer.println("    </div>");
            writer.println("    <div class='details'>");
            writer.println("        <h2>Details</h2>");
            writer.println("        " + details);
            writer.println("    </div>");
            writer.println("</body>");
            writer.println("</html>");
        }

        System.out.println("Report generated successfully: " + reportPath);
    }
}