package burp.vaycore.onescan.collect;

import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.bean.CollectReqResp;
import burp.vaycore.onescan.common.Constants;
import burp.vaycore.onescan.manager.CollectManager;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Web 目录名收集
 * <p>
 * Created by vaycore on 2023-12-25.
 */
public class WebNameCollect implements CollectManager.ICollectModule {

    @Override
    public String getName() {
        return "WebName";
    }

    @Override
    public List<String> doCollect(CollectReqResp reqResp) {
        // 只收集请求的数据
        if (!reqResp.isRequest()) {
            return null;
        }
        String path = parsePath(reqResp);
        if (path == null || !path.startsWith("/")) {
            return null;
        }
        // 根据斜杠数量，判断要不要处理
        int countMatches = StringUtils.countMatches(path, "/");
        if (countMatches <= 1) {
            return null;
        }
        int endIndex = path.indexOf("/", 1);
        // 可能存在双斜杠情况：'//'，所以 endIndex 需要大于 1 才行
        if (endIndex <= 1) {
            return null;
        }
        String webName = path.substring(1, endIndex);
        // 检测空值
        if (webName.trim().length() == 0) {
            return null;
        }
        // 包装数据，返回
        List<String> list = new ArrayList<>();
        list.add(webName);
        return list;
    }

    private String parsePath(CollectReqResp reqResp) {
        // 解析请求行
        String header = reqResp.getHeader();
        int offset = header.indexOf("\r\n");
        if (offset <= 0) {
            return null;
        }
        String reqLine = header.substring(0, offset);
        Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
        if (!matcher.find()) {
            return null;
        }
        int start = matcher.start(1);
        int end = matcher.end(1);
        String path = reqLine.substring(start, end);
        // 移除参数部分
        if (path.contains("?")) {
            path = path.substring(0, path.indexOf("?"));
        }
        // 移除锚点部分
        if (path.contains("#")) {
            path = path.substring(0, path.indexOf("#"));
        }
        return path;
    }
}
