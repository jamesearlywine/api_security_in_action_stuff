package com.manning.apisecurityinaction;

import spark.Request;
import spark.Response;

public class GlobalExceptionHandler {

    public static void badRequest(Exception ex, Request request, Response response) {
        response.status(400);
        response.body("{\"error\": \"" + ex + "\"}");
    }

    public static void emptyResult(Exception ex, Request request, Response response) {
        response.status(404);
    }
}
