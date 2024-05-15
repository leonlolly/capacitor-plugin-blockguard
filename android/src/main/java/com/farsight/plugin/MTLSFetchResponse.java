package com.farsight.plugin;

public class MTLSFetchResponse {

    public boolean success;
    public int statusCode;
    public String body;

    public MTLSFetchResponse(boolean success, int statusCode, String body) {
        this.success = success;
        this.statusCode = statusCode;
        this.body = body;
    }
}
