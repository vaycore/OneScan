package burp.vaycore.onescan.bean;

import burp.vaycore.common.utils.StringUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 指纹数据源提供者
 * <p>
 * Created by vaycore on 2025-05-13.
 */
public class FpDSProvider {

    private FpHttpReqDS request;
    private FpHttpRespDS response;

    private boolean _hasRequest;
    private boolean _hasResponse;

    public FpDSProvider(byte[] reqBytes, byte[] respBytes) {
        this(reqBytes, respBytes, StandardCharsets.UTF_8);
    }

    public FpDSProvider(byte[] reqBytes, byte[] respBytes, Charset charset) {
        this(reqBytes, respBytes, charset, charset);
    }

    public FpDSProvider(byte[] reqBytes, byte[] respBytes, Charset reqCharset, Charset respCharset) {
        // 解析请求数据
        try {
            this.request = new FpHttpReqDS(reqBytes, reqCharset);
            this._hasRequest = true;
        } catch (Exception e) {
            this._hasRequest = false;
        }
        // 解析响应数据
        try {
            this.response = new FpHttpRespDS(respBytes, respCharset);
            this._hasResponse = true;
        } catch (Exception e) {
            this._hasResponse = false;
        }
    }

    public String getCacheKey() {
        StringBuilder key = new StringBuilder();
        if (hasRequest()) {
            key.append(getRequest().calculateCacheKey());
        }
        if (hasResponse()) {
            key.append(getResponse().calculateCacheKey());
        }
        return key.toString();
    }

    public FpHttpReqDS getRequest() {
        return request;
    }

    public FpHttpRespDS getResponse() {
        return response;
    }

    public boolean hasRequest() {
        return _hasRequest;
    }

    public boolean hasResponse() {
        return _hasResponse;
    }

    /**
     * 获取用于匹配的数据
     *
     * @param dataSource 数据源
     * @param field      字段名
     */
    public String getMatchData(String dataSource, String field) {
        if (StringUtils.isEmpty(dataSource) || dataSource.startsWith("_")) {
            return "";
        }
        if (StringUtils.isEmpty(field) || field.startsWith("_")) {
            return "";
        }
        Object dataSourceObj = getValueByFieldName(this, dataSource);
        Object matchData = getValueByFieldName(dataSourceObj, field);
        return String.valueOf(matchData);
    }

    /**
     * 获取请求数据包中的 Host 数据
     *
     * @return 失败返回null
     */
    public String getRequestHost() {
        if (!hasRequest()) {
            return null;
        }
        String[] headers = getRequest().getHeader().split("\r\n");
        for (String header : headers) {
            if (header.startsWith("Host: ")) {
                return header.replace("Host: ", "");
            }
        }
        return null;
    }

    /**
     * 获取类的字段值列表
     *
     * @param clazz 类的实例
     * @return 失败返回空列表
     */
    protected static List<Field> getClassFields(Class<?> clazz) {
        List<Field> result = new ArrayList<>();
        if (clazz == null) {
            return result;
        }
        Field[] fields = clazz.getDeclaredFields();
        for (Field field : fields) {
            String fieldName = field.getName();
            // 忽略下划线标记的成员变量、忽略静态成员变量
            boolean isStatic = Modifier.isStatic(field.getModifiers());
            if (!fieldName.startsWith("_") && !isStatic) {
                result.add(field);
            }
        }
        // 获取父类的字段
        Class<?> superclass = clazz.getSuperclass();
        if (superclass != Object.class) {
            List<Field> superFields = getClassFields(superclass);
            result.addAll(superFields);
        }
        return result;
    }

    /**
     * 通过字段名，获取成员变量的值
     *
     * @param obj       对应的实例
     * @param fieldName 字段名
     * @return 失败返回空字符串
     */
    protected static Object getValueByFieldName(Object obj, String fieldName) {
        if (obj == null) {
            return "";
        }
        List<Field> fields = getClassFields(obj.getClass());
        Field field = fields.stream().filter(f -> f.getName().equals(fieldName))
                .findFirst().orElse(null);
        if (field == null) {
            return "";
        }
        field.setAccessible(true);
        try {
            return field.get(obj);
        } catch (IllegalAccessException e) {
            return "";
        }
    }
}
