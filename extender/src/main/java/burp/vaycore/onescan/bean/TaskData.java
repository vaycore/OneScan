package burp.vaycore.onescan.bean;

import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.manager.FpManager;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 任务数据
 * <p>
 * Created by vaycore on 2022-08-10.
 */
public class TaskData {

    // 序号（用于表格排序）
    private int id;

    // 数据来源
    private String from;

    // 请求方法
    private String method;

    // 主机
    private String host;

    // 请求路径
    private String url;

    // 响应页面标题
    private String title;

    // IP 地址
    private String ip;

    // 响应状态码
    private int status;

    // 响应长度（取 Content-Length 值）
    private int length;

    // 颜色标记
    private String highlight;

    // 自定义指纹数据参数
    private Map<String, String> params;

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

    public String getHighlight() {
        return highlight;
    }

    public void setHighlight(String highlight) {
        this.highlight = highlight;
    }

    public Map<String, String> getParams() {
        if (params == null) {
            params = new LinkedHashMap<>();
        }
        return params;
    }

    public void setParams(Map<String, String> params) {
        if (params == null) {
            this.params = new LinkedHashMap<>();
        } else {
            this.params = new LinkedHashMap<>(params);
        }
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
        List<Integer> colorLevels = new ArrayList<>();
        for (FpData item : list) {
            ArrayList<FpData.Param> itemParams = item.getParams();
            // 收集识别的指纹数据
            for (FpData.Param itemParam : itemParams) {
                String key = itemParam.getK();
                String value = itemParam.getV();
                Map<String, String> params = getParams();
                // key 不存在，添加数据
                if (!params.containsKey(key)) {
                    params.put(key, value);
                    continue;
                }
                // value 不能为空
                if (StringUtils.isEmpty(value)) {
                    continue;
                }
                // key 存在，拼接新值
                String newValue = getParams().get(key) + "," + value;
                params.put(key, newValue);
            }
            // 收集所有颜色等级
            String color = item.getColor();
            int level = FpManager.findColorLevelByName(color);
            colorLevels.add(level);
        }
        // 处理高亮颜色
        String highlight = FpManager.upgradeColors(colorLevels);
        setHighlight(highlight);
    }
}
