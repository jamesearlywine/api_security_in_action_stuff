package com.manning.apisecurityinaction;

import java.nio.file.*;

import com.manning.apisecurityinaction.controller.SpaceController;
import org.dalesbred.*;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.*;
import org.json.*;

import static spark.Spark.*;


public class Main {
    /**
     * Config
     */
    static final String DATABASE_URL = "jdbc:h2:mem:natter";
    static final String DATABASE_SUPERUSER_USERNAME = "natter";
    static final String DATABASE_SUPERUSER_PASSWORD = "password";
    static final String DATABASE_SERVICE_ACCOUNT_USERNAME = "natter_api_user";
    static final String DATABASE_SERVICE_ACCOUNT_PASSWORD = "password";

    static JdbcConnectionPool datasource;
    static Database database;

    static SpaceController spaceController;

    public static void main(String... args) throws Exception {
        useDbSuperUserAccount();
        initData();
        useDbServiceAccount();
        initControllers();
        defineRoutes();
        defineGlobalHandlers();
        registerErrorHandlers();
    }

    private static void useDbSuperUserAccount() {
        datasource = JdbcConnectionPool.create(
            DATABASE_URL, DATABASE_SUPERUSER_USERNAME, DATABASE_SUPERUSER_PASSWORD);
        database = Database.forDataSource(datasource);
    }


    private static void useDbServiceAccount() {
        datasource = JdbcConnectionPool.create(
            DATABASE_URL, DATABASE_SERVICE_ACCOUNT_USERNAME, DATABASE_SERVICE_ACCOUNT_PASSWORD);
        database = Database.forDataSource(datasource);
    }

    private static void initData() throws Exception {
        var path = Paths.get(Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));
    }

    private static void initControllers() {
        spaceController = new SpaceController(database);
    }

    private static void defineRoutes() {
        post("/spaces", spaceController::createSpace);
    }

    private static void defineGlobalHandlers() {

        before((
            (request, response) -> {
                if (request.requestMethod().equals("POST")
                 && !"application/json".equals(request.contentType())
                ) {
                    halt(415, new JSONObject().put("error", "Only application/json supported").toString());
                }
            }
        ));

        after((request, response) -> {
            response.type("application/json");
        });

        afterAfter((request, response) -> {
            response.header("Server", "");
            response.type("application/json; charset=utf-8");
            response.header("X-Content-Type-Options", "nosniff");
            response.header("X-Frame-Options", "deny");
            response.header("X-XSS-Protection", "1; mode=block");
            response.header("Cache-Control", "private, max-age=0");
            response.header("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'; sandbox");
            response.header("Server", "");
        });

        internalServerError(new JSONObject()
            .put("error", "internal server error").toString()
        );

        notFound(new JSONObject()
            .put("error", "not found").toString()
        );
    }

    private static void registerErrorHandlers() {
        exception(IllegalArgumentException.class, GlobalExceptionHandler::badRequest);
        exception(JSONException.class, GlobalExceptionHandler::badRequest);
        exception(EmptyResultException.class, GlobalExceptionHandler::emptyResult);
    }


}