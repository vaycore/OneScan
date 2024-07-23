package burp.vaycore.onescan.info;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import burp.IRequestInfo;
import burp.vaycore.common.helper.UIHelper;
import burp.vaycore.common.layout.VLayout;
import burp.vaycore.common.utils.JsonUtils;
import burp.vaycore.common.utils.StringUtils;
import burp.vaycore.onescan.bean.FpData;
import burp.vaycore.onescan.manager.FpManager;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * OneScan 信息辅助面板
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class OneScanInfoTab implements IMessageEditorTab {
   
   private final IExtensionHelpers mHelpers;
   private final JTabbedPane mTabPanel;
   private JList<String> mJsonKeyList;
   private JList<String> mFpNameList;

   public OneScanInfoTab(IBurpExtenderCallbacks callbacks) {
      mHelpers = callbacks.getHelpers();
      mTabPanel = new JTabbedPane();
   }

   public String getTabCaption() {
      return "OneScan";
   }

   public Component getUiComponent() {
      return mTabPanel;
   }

   public boolean isEnabled(byte[] content, boolean isRequest) {
      boolean hasJsonEnabled = hasBody(content) && JsonUtils.hasJson(getBody(content));
      if (isRequest) {
         return hasJsonEnabled;
      }
      List<FpData> fpData = FpManager.check(content);
      return hasJsonEnabled || !fpData.isEmpty();
   }

   public void setMessage(byte[] content, boolean isRequest) {
      mTabPanel.removeAll();
      if (!isRequest) {
         List<FpData> fpData = FpManager.check(content);
         if (!fpData.isEmpty()) {
            mTabPanel.addTab("Fingerprint", newFpPanel(fpData));
         }
      }
      String body = getBody(content);
      boolean hasJsonEnabled = hasBody(content) && JsonUtils.hasJson(body);
      if (hasJsonEnabled) {
         ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
         mTabPanel.addTab("Json", newJsonInfoPanel(keys));
      }
   }

   private JPanel newJsonInfoPanel(ArrayList<String> keys) {
      JPanel panel = new JPanel();
      panel.setLayout(new VLayout());
      mJsonKeyList = new JList<>(new Vector<>(keys));
      UIHelper.setListCellRenderer(mJsonKeyList);
      JScrollPane scrollPane = new JScrollPane(mJsonKeyList);
      panel.add(scrollPane, "1w");
      return panel;
   }

   private JPanel newFpPanel(List<FpData> fpData) {
      JPanel panel = new JPanel();
      panel.setLayout(new VLayout());
      String names = FpManager.listToNames(fpData);
      if (StringUtils.isNotEmpty(names)) {
         String[] data = names.split(",");
         mFpNameList = new JList<>(data);
         UIHelper.setListCellRenderer(mFpNameList);
         JScrollPane scrollPane = new JScrollPane(mFpNameList);
         panel.add(scrollPane, "1w");
      }
      return panel;
   }

   public byte[] getMessage() {
      return new byte[0];
   }

   public boolean isModified() {
      return false;
   }

   public byte[] getSelectedData() {
      int index = mTabPanel.getSelectedIndex();
      String title = mTabPanel.getTitleAt(index);
      List<String> keys;
      if ("Fingerprint".equals(title)) {
         keys = mFpNameList.getSelectedValuesList();
         return mHelpers.stringToBytes(StringUtils.join(keys, "\n"));
      } else if ("Json".equals(title)) {
         keys = mJsonKeyList.getSelectedValuesList();
         return mHelpers.stringToBytes(StringUtils.join(keys, "\n"));
      }
      return new byte[0];
   }

   private boolean hasBody(byte[] content) {
      IRequestInfo info = mHelpers.analyzeRequest(content);
      int bodyOffset = info.getBodyOffset();
      int bodySize = content.length - bodyOffset;
      return bodySize > 0;
   }

   private String getBody(byte[] content) {
      IRequestInfo info = mHelpers.analyzeRequest(content);
      int bodyOffset = info.getBodyOffset();
      int bodySize = content.length - bodyOffset;
      return new String(content, bodyOffset, bodySize);
   }
}
