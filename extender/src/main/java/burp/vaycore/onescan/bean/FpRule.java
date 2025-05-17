package burp.vaycore.onescan.bean;

import burp.vaycore.onescan.common.FpMethodHandler;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 指纹规则
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpRule implements Serializable {

    /**
     * 数据源
     */
    private String dataSource;

    /**
     * 匹配字段
     */
    private String field;

    /**
     * 匹配方法
     */
    private String method;

    /**
     * 匹配内容
     */
    private String content;

    public String getDataSource() {
        return dataSource;
    }

    public void setDataSource(String dataSource) {
        this.dataSource = dataSource;
    }

    public String getField() {
        return field;
    }

    public void setField(String field) {
        this.field = field;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    /**
     * 获取所有数据源
     *
     * @return 失败返回空列表
     */
    public static List<String> getDataSources() {
        List<Field> fields = FpDSProvider.getClassFields(FpDSProvider.class);
        return fields.stream().map(Field::getName).collect(Collectors.toList());
    }

    /**
     * 获取数据源下面的所有字段名
     *
     * @return 失败返回空列表
     */
    public static List<String> getFieldsByDataSource(String dataSource) {
        List<String> result = new ArrayList<>();
        List<Field> fields = FpDSProvider.getClassFields(FpDSProvider.class);
        Field field = fields.stream().filter(f -> f.getName().equals(dataSource))
                .findFirst().orElse(null);
        if (field == null) {
            return result;
        }
        List<Field> dataSourceClassFields = FpDSProvider.getClassFields(field.getType());
        return dataSourceClassFields.stream().map(Field::getName).collect(Collectors.toList());
    }

    /**
     * 获取所有匹配方法
     *
     * @return 失败返回空列表
     */
    public static List<String> getMethods() {
        String[] methods = FpMethodHandler.METHOD_ITEMS;
        return Arrays.asList(methods);
    }
}
