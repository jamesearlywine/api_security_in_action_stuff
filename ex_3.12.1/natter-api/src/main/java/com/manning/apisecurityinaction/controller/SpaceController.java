package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.controller.constants.HttpStatusCodes;
import org.dalesbred.Database;
import org.json.*;
import spark.*;

import java.sql.SQLException;

public class SpaceController {

    private static final Integer SPACE_NAME_MAX_LENGTH = 255;
    private static final Integer USER_NAME_MAX_LENGTH = 30;

    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
    }

    public JSONObject createSpace(Request request, Response response) throws SQLException {
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");
        var owner = json.getString("owner");

        if (spaceName.length() > SPACE_NAME_MAX_LENGTH) {
            throw new IllegalArgumentException("space name too long");
        }

        if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1" + (USER_NAME_MAX_LENGTH - 1) + "}")) {
            throw new IllegalArgumentException("invalid username");
        }

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");

            database.updateUnique(
                "INSERT INTO SPACES(space_id, name, owner) " +
                    "VALUES(?, ?, ?);", spaceId, spaceName, owner
            );

            response.status(HttpStatusCodes.CREATED);
            response.header("Location", "/spaces/" + spaceId);

            return new JSONObject()
                .put("name", spaceName)
                .put("uri", "/spaces/" + spaceId)
            ;
        });
    }
}
