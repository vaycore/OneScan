package burp.vaycore.onescan.bean;

import burp.vaycore.common.utils.FileUtils;
import burp.vaycore.common.utils.GsonUtils;
import burp.vaycore.onescan.manager.FpManager;

import java.util.ArrayList;
import java.util.List;

/**
 * 指纹配置
 * <p>
 * Created by vaycore on 2025-05-19.
 */
public class FpConfig {

    /**
     * 指纹字段
     */
    private List<FpColumn> columns;

    /**
     * 指纹数据
     */
    private List<FpData> list;

    /**
     * 获取指纹字段列表
     *
     * @return 失败返回空列表
     */
    public List<FpColumn> getColumns() {
        if (columns == null) {
            columns = new ArrayList<>();
        }
        return columns;
    }

    /**
     * 获取指纹字段数量
     *
     * @return 指纹字段数量
     */
    public int getColumnsSize() {
        if (columns == null || columns.isEmpty()) {
            return 0;
        }
        return columns.size();
    }

    /**
     * 添加指纹字段
     *
     * @param column 指纹字段数据实例
     */
    public void addColumnsItem(FpColumn column) {
        if (column != null) {
            columns.add(column);
            writeToFile();
        }
    }

    /**
     * 移除指纹字段数据
     *
     * @param index 数据下标
     * @return 移除的字段数据实例
     */
    public FpColumn removeColumnsItem(int index) {
        if (index >= 0 && index < getColumnsSize()) {
            FpColumn column = columns.remove(index);
            writeToFile();
            return column;
        }
        return null;
    }

    /**
     * 更新指纹字段数据
     *
     * @param index  下标
     * @param column 指纹字段实例
     */
    public void setColumnsItem(int index, FpColumn column) {
        if (column == null || getColumnsSize() == 0) {
            return;
        }
        if (index < 0 || index >= getColumnsSize()) {
            return;
        }
        columns.set(index, column);
        writeToFile();
    }

    /**
     * 设置指纹字段列表
     *
     * @param columns 指纹字段列表
     */
    public void setColumns(ArrayList<FpColumn> columns) {
        if (columns == null) {
            this.columns = new ArrayList<>();
        } else {
            this.columns = new ArrayList<>(columns);
        }
        writeToFile();
    }

    /**
     * 获取指纹数据列表
     *
     * @return 失败返回空列表
     */
    public List<FpData> getList() {
        if (list == null) {
            list = new ArrayList<>();
        }
        return list;
    }

    /**
     * 获取指纹数据数量
     *
     * @return 指纹数量
     */
    public int getListSize() {
        if (list == null || list.isEmpty()) {
            return 0;
        }
        return list.size();
    }


    /**
     * 添加指纹数据
     *
     * @param data 指纹数据实例
     */
    public void addListItem(FpData data) {
        if (data != null && !data.getRules().isEmpty()) {
            list.add(data);
            writeToFile();
        }
    }

    /**
     * 移除指纹数据
     *
     * @param index 数据下标
     */
    public void removeListItem(int index) {
        if (index >= 0 && index < getListSize()) {
            list.remove(index);
            writeToFile();
        }
    }

    /**
     * 更新指纹数据
     *
     * @param index 下标
     * @param data  指纹数据实例
     */
    public void setListItem(int index, FpData data) {
        if (getListSize() == 0) {
            return;
        }
        if (index < 0 || index >= getListSize()) {
            return;
        }
        if (data != null && !data.getRules().isEmpty()) {
            list.set(index, data);
            writeToFile();
        }
    }

    /**
     * 设置指纹数据列表
     *
     * @param list 数据列表
     */
    public void setList(List<FpData> list) {
        if (list == null) {
            this.list = new ArrayList<>();
        } else {
            this.list = new ArrayList<>(list);
        }
        writeToFile();
    }

    /**
     * 写入配置到文件中
     */
    private void writeToFile() {
        // 后台保存
        new Thread(() -> {
            synchronized (FpConfig.class) {
                String json = GsonUtils.toJson(this);
                FileUtils.writeFile(FpManager.getPath(), json);
            }
        }).start();
    }
}
