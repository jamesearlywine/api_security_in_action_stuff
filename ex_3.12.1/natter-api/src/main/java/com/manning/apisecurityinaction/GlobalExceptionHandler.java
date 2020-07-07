package com.manning.apisecurityinaction;

import com.manning.apisecurityinaction.controller.constants.HttpStatusCodes;
import spark.Request;
import spark.Response;

public class GlobalExceptionHandler {

    public static void badRequest(Exception ex, Request request, Response response) {
        response.status(HttpStatusCodes.BAD_REQUEST);
        response.body("{\"error\": \"" + ex + "\"}");
    }

    public static void emptyResult(Exception ex, Request request, Response response) {
        response.status(HttpStatusCodes.NOT_FOUND);
    }
}
