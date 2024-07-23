package burp;
/*
 * @(#)IHttpHeader.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to hold details about an HTTP/2 header.
 */
public interface IHttpHeader
{
    /**
     * This method is used to retrieve the name of the header.
     * @return The name of the header.
     */
    String getName();

    /**
     * This method is used to retrieve the value of the header.
     * @return The value of the header.
     */
    String getValue();
}
