package burp.vaycore.common.helper;

import burp.vaycore.common.log.Logger;
import burp.vaycore.onescan.common.L;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.*;

/**
 * UI辅助类
 * <p>
 * Created by vaycore on 2022-08-08.
 */
public class UIHelper {

    /**
     * 当前主窗口实例缓存
     */
    private static Frame sMainFrame;

    private UIHelper() {
        throw new IllegalAccessError("UIHelper class not support create instance.");
    }

    /**
     * 设置列表间隔底色
     *
     * @param listView 列表组件
     */
    public static void setListCellRenderer(JList<?> listView) {
        if (listView == null || listView.getCellRenderer() == null) {
            return;
        }
        final ListCellRenderer renderer = listView.getCellRenderer();
        listView.setCellRenderer((list, value, index, isSelected, cellHasFocus) -> {
            Component component = renderer.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (isSelected) {
                return component;
            }
            Color bgColor;
            if (index % 2 == 0) {
                bgColor = UIManager.getColor("Table.background");
            } else {
                bgColor = UIManager.getColor("Table.alternateRowColor");
            }
            component.setBackground(bgColor);
            return component;
        });
    }

    /**
     * 获取所有的配置颜色
     *
     * @return 颜色配置key列表
     */
    public static List<String> getColorKeys() {
        List<String> colorKeys = new ArrayList<>();
        Set<Map.Entry<Object, Object>> entries = UIManager.getLookAndFeelDefaults().entrySet();
        for (Map.Entry<Object, Object> entry : entries) {
            if (entry.getValue() instanceof Color) {
                colorKeys.add(entry.getKey().toString());
            }
        }
        // sort the color keys
        Collections.sort(colorKeys);
        return colorKeys;
    }

    /**
     * 显示文件选择器
     *
     * @param title             对话框标题
     * @param defaultSelectFile 默认选择的文件
     * @return 返回选择的文件绝对路径
     */
    public static String selectFileDialog(String title, String defaultSelectFile) {
        return selectFileDialog(title, new File(defaultSelectFile));
    }

    /**
     * 显示文件选择器
     *
     * @param title       对话框标题
     * @param defaultFile 默认选择的文件
     * @return 返回选择的文件绝对路径
     */
    public static String selectFileDialog(String title, File defaultFile) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setDialogTitle(title);
        chooser.setSelectedFile(defaultFile);
        int resultCode = chooser.showOpenDialog(UIHelper.getMainFrame());
        // 状态检测
        if (resultCode != JFileChooser.APPROVE_OPTION) {
            return defaultFile.toString();
        }
        return chooser.getSelectedFile().toString();
    }

    /**
     * 显示目录选择器
     *
     * @param title            对话框标题
     * @param defaultSelectDir 默认选择的目录
     * @return 返回选择的目录绝对路径
     */
    public static String selectDirDialog(String title, String defaultSelectDir) {
        return selectDirDialog(title, new File(defaultSelectDir));
    }

    /**
     * 显示目录选择器
     *
     * @param title      对话框标题
     * @param defaultDir 默认选择的目录
     * @return 返回选择的目录绝对路径
     */
    public static String selectDirDialog(String title, File defaultDir) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle(title);
        chooser.setSelectedFile(defaultDir);
        int resultCode = chooser.showOpenDialog(UIHelper.getMainFrame());
        // 状态检测
        if (resultCode != JFileChooser.APPROVE_OPTION) {
            return defaultDir.toString();
        }
        return chooser.getSelectedFile().toString();
    }

    public static void setTableHeaderAlign(JTable table, int align) {
        if (table == null || table.getTableHeader() == null) {
            return;
        }
        TableCellRenderer thr = table.getTableHeader().getDefaultRenderer();
        if (!(thr instanceof JLabel)) {
            return;
        }
        JLabel headerLabel = (JLabel) thr;
        switch (align) {
            case SwingConstants.LEFT:
            case SwingConstants.RIGHT:
                headerLabel.setHorizontalAlignment(align);
                break;
            case SwingConstants.TOP:
            case SwingConstants.BOTTOM:
                headerLabel.setVerticalAlignment(align);
                break;
            case SwingConstants.CENTER:
                headerLabel.setHorizontalAlignment(align);
                headerLabel.setVerticalAlignment(align);
                break;
        }
        table.getTableHeader().setDefaultRenderer(thr);
    }

    public static void showTipsDialog(String message) {
        showTipsDialog(L.get("hint"), message);
    }

    public static void showTipsDialog(String message, Component parentComponent) {
        showTipsDialog(L.get("hint"), message, parentComponent);
    }

    public static void showTipsDialog(String title, String message) {
        showTipsDialog(title, message, UIHelper.getMainFrame());
    }

    public static void showTipsDialog(String title, String message, Component parentComponent) {
        JOptionPane.showConfirmDialog(parentComponent, message, title, JOptionPane.DEFAULT_OPTION);
    }

    /**
     * 显示含有确定、取消的消息提示对话框
     *
     * @param message 提示消息
     * @return 用户的选择（{@link JOptionPane#OK_OPTION} or {@link JOptionPane#CANCEL_OPTION}）
     */
    public static int showOkCancelDialog(String message) {
        return showOkCancelDialog(L.get("hint"), message);
    }

    /**
     * 显示含有确定、取消的消息提示对话框
     *
     * @param message         提示消息
     * @param parentComponent 父级组件
     * @return 用户的选择（{@link JOptionPane#OK_OPTION} or {@link JOptionPane#CANCEL_OPTION}）
     */
    public static int showOkCancelDialog(String message, Component parentComponent) {
        return showOkCancelDialog(L.get("hint"), message, parentComponent);
    }

    /**
     * 显示含有确定、取消的消息提示对话框
     *
     * @param title   标题
     * @param message 消息
     * @return 用户的选择（{@link JOptionPane#OK_OPTION} or {@link JOptionPane#CANCEL_OPTION}）
     */
    public static int showOkCancelDialog(String title, String message) {
        return showOkCancelDialog(title, message, UIHelper.getMainFrame());
    }

    /**
     * 显示含有确定、取消的消息提示对话框
     *
     * @param title           标题
     * @param message         消息
     * @param parentComponent 父级组件
     * @return 用户的选择（{@link JOptionPane#OK_OPTION} or {@link JOptionPane#CANCEL_OPTION}）
     */
    public static int showOkCancelDialog(String title, String message, Component parentComponent) {
        return JOptionPane.showConfirmDialog(parentComponent, message, title,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
    }

    /**
     * 显示含有确定、取消的自定义组件对话框
     *
     * @param title 标题
     * @param c     组件
     * @return 用户的选择（{@link JOptionPane#OK_OPTION} or {@link JOptionPane#CANCEL_OPTION}）
     */
    public static int showCustomDialog(String title, JComponent c) {
        return showCustomDialog(title, c, UIHelper.getMainFrame());
    }

    /**
     * 显示含有确定、取消的自定义组件对话框
     *
     * @param title           标题
     * @param c               组件
     * @param parentComponent 父级组件
     * @return 用户的选择（{@link JOptionPane#OK_OPTION} or {@link JOptionPane#CANCEL_OPTION}）
     */
    public static int showCustomDialog(String title, JComponent c, Component parentComponent) {
        return JOptionPane.showConfirmDialog(parentComponent, c, title,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
    }

    /**
     * 显示含有确定、取消的自定义组件对话框
     *
     * @param title 标题
     * @param c     组件
     * @return 用户的选择（{@link JOptionPane#OK_OPTION} or {@link JOptionPane#CANCEL_OPTION}）
     */
    public static int showCustomDialog(String title, String[] options, JComponent c) {
        return showCustomDialog(title, options, c, UIHelper.getMainFrame());
    }

    /**
     * 显示含有确定、取消的自定义组件对话框
     *
     * @param title           标题
     * @param c               组件
     * @param parentComponent 父级组件
     * @return 用户的选择（{@link JOptionPane#OK_OPTION} or {@link JOptionPane#CANCEL_OPTION}）
     */
    public static int showCustomDialog(String title, String[] options, JComponent c, Component parentComponent) {
        return JOptionPane.showOptionDialog(parentComponent, c, title,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]);
    }

    /**
     * 将 JRadioButton 组件进行分组
     *
     * @param buttons 一个或多个 JRadioButton 组件
     */
    public static void createRadioGroup(JRadioButton... buttons) {
        if (buttons == null || buttons.length == 0) {
            return;
        }
        ButtonGroup group = new ButtonGroup();
        for (JRadioButton button : buttons) {
            if (button == null) {
                continue;
            }
            group.add(button);
        }
    }

    /**
     * 刷新UI
     *
     * @param c 组件
     */
    public static void refreshUI(Component c) {
        if (c == null) {
            return;
        }
        //SwingUtilities.updateComponentTreeUI(c);
        c.invalidate();
        c.validate();
        c.repaint();
    }

    /**
     * 获取当前程序的主窗口
     *
     * @return 失败返回 null
     */
    public static Frame getMainFrame() {
        if (sMainFrame != null) {
            return sMainFrame;
        }
        Frame[] frames = Frame.getFrames();
        JFrame mainFrame = null;
        for (Frame frame : frames) {
            // 取第一个可见的 JFrame 实例
            if (frame instanceof JFrame && frame.isVisible()) {
                mainFrame = (JFrame) frame;
                break;
            }
        }
        sMainFrame = mainFrame;
        return mainFrame;
    }

    /**
     * 在日志中打印所有内置的颜色值
     */
    private static void printColorKeys() {
        List<String> colorKeys = getColorKeys();
        for (String colorKey : colorKeys) {
            Color color = UIManager.getColor(colorKey);
            Logger.debug("%s, [r=%s, g=%s, b=%s]", colorKey, color.getRed(), color.getGreen(), color.getBlue());
        }
    }
}
