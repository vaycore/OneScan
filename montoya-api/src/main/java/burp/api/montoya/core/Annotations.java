/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.core;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Annotations stored with requests and responses in Burp Suite.
 */
public interface Annotations
{
    /**
     * @return the notes
     */
    String notes();

    /**
     * @return True if there are any notes for this HTTP request and response.
     */
    boolean hasNotes();

    /**
     * @return True if there is a highlight color for this HTTP request and response.
     */
    boolean hasHighlightColor();

    /**
     * Set (mutate) the current annotations notes value
     *
     * @param notes the notes to set on the current annotations
     */
    void setNotes(String notes);

    /**
     * @return the highlight color;
     */
    HighlightColor highlightColor();

    /**
     * Set (mutate) the current annotations highlight color value
     *
     * @param highlightColor the highlight color to set on the current annotations
     */
    void setHighlightColor(HighlightColor highlightColor);

    /**
     * Create a copy of the annotations with new notes.
     *
     * @param notes The new notes.
     *
     * @return The new annotations.
     */
    Annotations withNotes(String notes);

    /**
     * Create a copy of the annotations with a new highlight color.
     *
     * @param highlightColor The new highlight color.
     *
     * @return The new annotations.
     */
    Annotations withHighlightColor(HighlightColor highlightColor);

    /**
     * Create a new empty annotations.
     *
     * @return The annotations.
     */
    static Annotations annotations()
    {
        return FACTORY.annotations();
    }

    /**
     * Create a new annotations with notes.
     *
     * @param notes The notes of the annotations
     *
     * @return The annotations.
     */
    static Annotations annotations(String notes)
    {
        return FACTORY.annotations(notes);
    }

    /**
     * Create a new annotations with a highlight color.
     *
     * @param highlightColor The highlight color of the annotations
     *
     * @return The annotations.
     */
    static Annotations annotations(HighlightColor highlightColor)
    {
        return FACTORY.annotations(highlightColor);
    }

    /**
     * Create a new annotations with notes and a highlight color.
     *
     * @param notes        The notes of the annotations
     * @param highlightColor The highlight color of the annotations
     *
     * @return The annotations.
     */
    static Annotations annotations(String notes, HighlightColor highlightColor)
    {
        return FACTORY.annotations(notes, highlightColor);
    }
}
