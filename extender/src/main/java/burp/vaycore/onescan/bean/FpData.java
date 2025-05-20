package burp.vaycore.onescan.bean;

import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.manager.FpManager;

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
     * 指纹数据参数
     */
    private ArrayList<Param> params;

    /**
     * 颜色
     */
    private String color;

    /**
     * 指纹规则
     */
    private ArrayList<ArrayList<FpRule>> rules;

    public ArrayList<Param> getParams() {
        if (params == null) {
            params = new ArrayList<>();
        }
        return params;
    }

    public void setParams(ArrayList<Param> params) {
        this.params = params;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public ArrayList<ArrayList<FpRule>> getRules() {
        if (rules == null) {
            rules = new ArrayList<>();
        }
        return this.rules;
    }

    public void setRules(ArrayList<ArrayList<FpRule>> rules) {
        this.rules = rules;
    }

    public String toInfo() {
        StringBuilder sb = new StringBuilder();
        // 拼接指纹数据字段值
        ArrayList<FpData.Param> params = getParams();
        if (params != null && !params.isEmpty()) {
            for (FpData.Param param : params) {
                String key = param.getK();
                String value = param.getV();
                String columnName = FpManager.findColumnNameById(key);
                if (StringUtils.isNotEmpty(value)) {
                    sb.append(columnName).append("=").append(value).append(",");
                }
            }
        }
        // 拼接指纹数据的颜色值
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
        return Objects.equals(params, fpData.params) &&
                Objects.equals(color, fpData.color) &&
                Objects.equals(rules, fpData.rules);
    }

    @Override
    public int hashCode() {
        return Objects.hash(params, color, rules);
    }

    /**
     * 指纹数据参数
     */
    public static class Param implements Serializable {

        private String k;
        private String v;

        public Param(String k, String v) {
            this.k = k;
            this.v = v;
        }

        public String getK() {
            return k;
        }

        public void setK(String k) {
            this.k = k;
        }

        public String getV() {
            return v;
        }

        public void setV(String v) {
            this.v = v;
        }
    }
}
