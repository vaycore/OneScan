package burp.vaycore.onescan.ui.widget;

import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.HLayout;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.common.utils.Utils;
import burp.vaycore.common.widget.HintTextField;
import burp.vaycore.onescan.common.L;
import burp.vaycore.onescan.common.OnDataChangeListener;

import javax.swing.*;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 简单的字典列表展示
 * <p>
 * Created by vaycore on 2022-08-08.
 */
public class SimpleWordlist extends JPanel implements ActionListener, ListDataListener {

    private final DefaultListModel<String> mListModel;
    private HintTextField mTfInputItem;
    private JList<String> mListView;
    private String mAction;
    private OnDataChangeListener mOnDataChangeListener;

    public SimpleWordlist() {
        this(null);
    }

    public SimpleWordlist(List<String> wordlist) {
        mListModel = new DefaultListModel<>();
        mListModel.addListDataListener(this);
        initData(wordlist);
        initView();
    }

    public void setActionCommand(String action) {
        this.mAction = action;
    }

    public String getActionCommand() {
        if (StringUtils.isEmpty(this.mAction)) {
            return toString();
        }
        return this.mAction;
    }

    private void initData(List<String> wordlist) {
        setListData(wordlist);
    }

    /**
     * 设置列表数据
     *
     * @param list 数据列表
     */
    public void setListData(List<String> list) {
        if (list == null) {
            return;
        }
        // 切换时数据量过大，可能造成卡顿，先临时取消监听器；设置完成数据后再添加回来
        mListModel.removeListDataListener(this);
        mListModel.removeAllElements();
        for (String item : list) {
            mListModel.addElement(item);
        }
        mListModel.addListDataListener(this);
        // 手动调用数据更新
        dataChanged();
    }

    /**
     * 获取列表数据
     *
     * @return 列表数据
     */
    public List<String> getListData() {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < mListModel.size(); i++) {
            result.add(mListModel.get(i));
        }
        return result;
    }

    /**
     * 列表数据是否为空
     */
    public boolean isEmptyListData() {
        return mListModel == null || mListModel.isEmpty();
    }

    /**
     * 添加数据修改监听器
     *
     * @param l 监听器
     */
    public void setOnDataChangeListener(OnDataChangeListener l) {
        this.mOnDataChangeListener = l;
    }

    private void initView() {
        setLayout(new HLayout(5));
        setPreferredSize(new Dimension(0, 240));

        add(newLeftPanel(), "85px");
        add(newRightPanel(), "350px");
    }

    private JPanel newLeftPanel() {
        JPanel panel = new JPanel(new VLayout(3));
        panel.add(newButton(L.get("paste"), "paste-item"));
        panel.add(newButton(L.get("remove"), "remove-item"));
        panel.add(newButton(L.get("clear"), "clear-item"));
        panel.add(newButton(L.get("up"), "up-item"));
        panel.add(newButton(L.get("down"), "down-item"));
        panel.add(newButton(L.get("unique"), "unique-item"));
        panel.add(new Panel(), "1w");
        panel.add(newButton(L.get("add"), "add-input-item"));
        return panel;
    }

    private JButton newButton(String text, String action) {
        JButton button = new JButton(text);
        button.setActionCommand(action);
        button.addActionListener(this);
        return button;
    }

    private JPanel newRightPanel() {
        JPanel panel = new JPanel(new VLayout(10));
        mListView = new JList<>(mListModel);
        UIHelper.setListCellRenderer(mListView);
        JScrollPane scrollPane = new JScrollPane(mListView);
        panel.add(scrollPane, "1w");

        mTfInputItem = new HintTextField();
        mTfInputItem.setHintText(L.get("enter_a_new_item"));
        mTfInputItem.setActionCommand("add-input-item");
        mTfInputItem.addActionListener(this);
        panel.add(mTfInputItem);
        return panel;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String action = e.getActionCommand();
        switch (action) {
            case "paste-item":
                pasteItem();
                break;
            case "add-input-item":
                String inputItem = mTfInputItem.getText();
                if (StringUtils.isNotEmpty(inputItem)) {
                    mListModel.addElement(inputItem);
                    mTfInputItem.setText("");
                }
                mTfInputItem.requestFocus();
                break;
            case "clear-item":
                int state = UIHelper.showOkCancelDialog(L.get("confirm_clear_the_list_hint"));
                if (state == JOptionPane.OK_OPTION) {
                    mListModel.removeAllElements();
                }
                break;
            case "unique-item":
                uniqueItem();
                break;
        }
        // 以下是需要用到选中下标才能进行操作
        int index = mListView.getSelectedIndex();
        if (index < 0 || index >= mListModel.getSize()) {
            return;
        }
        switch (action) {
            case "remove-item":
                mListModel.removeElementAt(index);
                if (index > 0) {
                    mListView.setSelectedIndex(--index);
                } else {
                    mListView.setSelectedIndex(0);
                }
                break;
            case "up-item":
                int upIndex = index - 1;
                if (upIndex >= 0) {
                    String temp = mListModel.get(upIndex);
                    mListModel.setElementAt(mListModel.get(index), upIndex);
                    mListModel.setElementAt(temp, index);
                    mListView.setSelectedIndex(upIndex);
                }
                break;
            case "down-item":
                int downIndex = index + 1;
                if (downIndex < mListModel.size()) {
                    String temp = mListModel.get(index);
                    mListModel.setElementAt(mListModel.get(downIndex), index);
                    mListModel.setElementAt(temp, downIndex);
                    mListView.setSelectedIndex(downIndex);
                }
                break;
            default:
                break;
        }
    }

    /**
     * 粘贴
     */
    private void pasteItem() {
        String text = Utils.getSysClipboardText();
        if (StringUtils.isEmpty(text)) {
            return;
        }
        // 先处理换行
        String[] lines = null;
        if (text.contains("\r\n")) {
            lines = text.split("\r\n");
        } else if (text.contains("\n")) {
            lines = text.split("\n");
        }
        // 无换行符号，添加到列表
        if (lines == null || lines.length == 0) {
            mListModel.addElement(text);
        } else {
            // 过滤空的字符串，转换为 List 实例
            List<String> list = Arrays.stream(lines)
                    .filter(StringUtils::isNotEmpty)
                    .collect(Collectors.toList());
            // 添加到列表展示
            List<String> listData = getListData();
            listData.addAll(list);
            setListData(listData);
        }
    }

    /**
     * 去重
     */
    private void uniqueItem() {
        int size = mListModel.size();
        if (size <= 0) {
            return;
        }
        List<String> list = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            String value = mListModel.get(i);
            if (list.contains(value)) {
                continue;
            }
            list.add(value);
        }
        setListData(list);
    }

    @Override
    public void intervalAdded(ListDataEvent e) {
        dataChanged();
    }

    @Override
    public void intervalRemoved(ListDataEvent e) {
        dataChanged();
    }

    @Override
    public void contentsChanged(ListDataEvent e) {
        dataChanged();
    }

    /**
     * 列表数据有修改
     */
    private void dataChanged() {
        if (mOnDataChangeListener != null) {
            mOnDataChangeListener.onDataChange(getActionCommand());
        }
    }
}
