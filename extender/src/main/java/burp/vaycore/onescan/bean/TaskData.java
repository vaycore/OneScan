package burp.vaycore.onescan.bean;

import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.manager.FpManager;

import java.util.ArrayList;
import java.util.List;

/**
 * 任务数据
 * <p>
 * Created by vaycore on 2022-08-10.
 */
public class TaskData {
    // 展示的数据
    private int id;
    private String from;
    private String method;
    private String host;
    private String url;
    private String title;
    private String ip;
    private int status;
    private int length;
    private String application;
    private String webserver;
    private String os;
    private String lang;
    private String framework;
    private String description;
    private String highlight;
    // 请求响应数据
    private Object reqResp;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public String getApplication() {
        return application;
    }

    public void setApplication(String application) {
        this.application = application;
    }

    public String getWebserver() {
        return webserver;
    }

    public void setWebserver(String webserver) {
        this.webserver = webserver;
    }

    public String getOS() {
        return os;
    }

    public void setOS(String os) {
        this.os = os;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getFramework() {
        return framework;
    }

    public void setFramework(String framework) {
        this.framework = framework;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getHighlight() {
        return highlight;
    }

    public void setHighlight(String highlight) {
        this.highlight = highlight;
    }

    public Object getReqResp() {
        return reqResp;
    }

    public void setReqResp(Object reqResp) {
        this.reqResp = reqResp;
    }

    public void setFingerprint(List<FpData> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        StringBuilder application = newStringBuilder(getApplication());
        StringBuilder webserver = newStringBuilder(getWebserver());
        StringBuilder os = newStringBuilder(getOS());
        StringBuilder lang = newStringBuilder(getLang());
        StringBuilder framework = newStringBuilder(getFramework());
        StringBuilder description = newStringBuilder(getDescription());
        List<Integer> colorLevels = new ArrayList<>();
        for (FpData item : list) {
            // 收集指纹数据
            appendData(application, item.getApplication());
            appendData(webserver, item.getWebserver());
            appendData(os, item.getOS());
            appendData(lang, item.getLang());
            appendData(framework, item.getFramework());
            appendData(description, item.getDescription());
            // 收集所有颜色等级
            String color = item.getColor();
            int level = FpManager.findColorLevelByName(color);
            colorLevels.add(level);
        }
        // 填充指纹数据
        setApplication(application.toString());
        setWebserver(webserver.toString());
        setOS(os.toString());
        setLang(lang.toString());
        setFramework(framework.toString());
        setDescription(description.toString());
        // 处理高亮颜色
        String highlight = FpManager.upgradeColors(colorLevels);
        setHighlight(highlight);
    }

    private StringBuilder newStringBuilder(String text) {
        StringBuilder result = new StringBuilder();
        if (StringUtils.isNotEmpty(text)) {
            return result.append(text);
        }
        return result;
    }

    private void appendData(StringBuilder sb, String data) {
        if (StringUtils.isEmpty(data) || sb.indexOf(data) >= 0) {
            return;
        }
        if (StringUtils.isNotEmpty(sb)) {
            sb.append(",");
        }
        sb.append(data);
    }
}
