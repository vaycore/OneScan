package burp.vaycore.onescan.bean;

import burp.vaycore.common.utils.StringUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Objects;

/**
 * 指纹数据
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpData implements Serializable {

    /**
     * 应用程序
     */
    private String application;

    /**
     * Web服务器
     */
    private String webserver;

    /**
     * 操作系统
     */
    private String os;

    /**
     * 编程语言
     */
    private String lang;

    /**
     * 开发框架
     */
    private String framework;

    /**
     * 描述信息
     */
    private String description;

    /**
     * 颜色
     */
    private String color;

    /**
     * 指纹规则
     */
    private ArrayList<ArrayList<FpRule>> rules;

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

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public ArrayList<ArrayList<FpRule>> getRules() {
        return this.rules;
    }

    public void setRules(ArrayList<ArrayList<FpRule>> rules) {
        this.rules = rules;
    }

    public String toInfo() {
        StringBuilder sb = new StringBuilder();
        if (StringUtils.isNotEmpty(this.application)) {
            sb.append("App=").append(this.application).append(", ");
        }
        if (StringUtils.isNotEmpty(this.webserver)) {
            sb.append("WebServer=").append(this.webserver).append(", ");
        }
        if (StringUtils.isNotEmpty(this.os)) {
            sb.append("OS=").append(this.os).append(", ");
        }
        if (StringUtils.isNotEmpty(this.lang)) {
            sb.append("Lang=").append(this.lang).append(", ");
        }
        if (StringUtils.isNotEmpty(this.framework)) {
            sb.append("Frame=").append(this.framework).append(", ");
        }
        if (StringUtils.isNotEmpty(this.description)) {
            sb.append("Desc=").append(this.description).append(", ");
        }
        if (StringUtils.isNotEmpty(this.color)) {
            sb.append("Color=").append(this.color).append(", ");
        }
        if (StringUtils.isEmpty(sb)) {
            return "";
        }
        return sb.substring(0, sb.lastIndexOf(", "));
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        FpData fpData = (FpData) o;
        return Objects.equals(application, fpData.application) &&
                Objects.equals(webserver, fpData.webserver) &&
                Objects.equals(os, fpData.os) &&
                Objects.equals(lang, fpData.lang) &&
                Objects.equals(framework, fpData.framework) &&
                Objects.equals(description, fpData.description) &&
                Objects.equals(color, fpData.color) &&
                Objects.equals(rules, fpData.rules);
    }

    @Override
    public int hashCode() {
        return Objects.hash(application, webserver, os, lang, framework, description, color, rules);
    }
}
