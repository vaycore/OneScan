package burp.hae.montoya.ui;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;

/**
 * <p>
 * Created by vaycore on 2024-05-07.
 */
public class EditorCreationContextImpl implements EditorCreationContext, ToolSource {

    private final ToolType type;
    private final EditorMode mode;

    public EditorCreationContextImpl(ToolType type) {
        this(type, EditorMode.READ_ONLY);
    }

    public EditorCreationContextImpl(ToolType type, EditorMode mode) {
        this.type = type;
        this.mode = mode;
    }

    @Override
    public ToolSource toolSource() {
        return this;
    }

    @Override
    public EditorMode editorMode() {
        return this.mode;
    }

    @Override
    public ToolType toolType() {
        return this.type;
    }

    @Override
    public boolean isFromTool(ToolType... toolType) {
        return false;
    }
}
