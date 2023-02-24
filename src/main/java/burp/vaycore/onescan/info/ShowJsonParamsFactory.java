package burp.vaycore.onescan.info;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class ShowJsonParamsFactory implements IMessageEditorTabFactory {

   private IBurpExtenderCallbacks mCallbacks;

   public ShowJsonParamsFactory(IBurpExtenderCallbacks callbacks) {
      this.mCallbacks = callbacks;
   }

   public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
      return new ShowJsonParamsTab(this.mCallbacks);
   }
}
