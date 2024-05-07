package burp.hae;

import burp.IHttpService;
import burp.IMessageEditorController;

/**
 * 请求响应编辑器组件的控制器
 * <p>
 * Created by vaycore on 2024-05-07.
 */
public class MessageEditorController implements IMessageEditorController {

    private IHttpService service;
    private byte[] request;
    private byte[] response;

    @Override
    public IHttpService getHttpService() {
        return this.service;
    }

    @Override
    public byte[] getRequest() {
        if (this.request == null || this.request.length == 0) {
            return new byte[0];
        }
        return this.request;
    }

    @Override
    public byte[] getResponse() {
        if (this.response == null || this.response.length == 0) {
            return new byte[0];
        }
        return this.response;
    }

    public void setHttpService(IHttpService service) {
        this.service = service;
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }
}
