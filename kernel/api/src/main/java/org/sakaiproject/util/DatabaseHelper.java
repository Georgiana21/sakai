package org.sakaiproject.util;

import com.mysql.jdbc.jdbc2.optional.MysqlDataSource;

import javax.sql.rowset.serial.SerialBlob;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

public class DatabaseHelper {

    private static DatabaseHelper instance;
    private MysqlDataSource dataSource;

    private DatabaseHelper(){
        dataSource = new MysqlDataSource();
        dataSource.setUser("sakaiuser");
        dataSource.setPassword("sakaipassword");
        dataSource.setServerName("localhost");
        dataSource.setPortNumber(3306);
        dataSource.setDatabaseName("sakaidatabase");
    }

    public static DatabaseHelper getInstance(){
        if(instance == null)
            instance = new DatabaseHelper();
        return instance;
    }

    public void saveUser(String username, byte[] template) throws SQLException {
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("insert into sakai_user_fingerprint(eid,fingerprint) values(?,?)");
        statement.setString(1,username);
        Blob blob = new SerialBlob(template);
        statement.setBlob(2, blob);
        statement.executeUpdate();
        statement.close();
        connection.close();
    }

    public boolean userExists(String eid) throws SQLException {
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("select * from sakai_user_id_map where eid=?");
        statement.setString(1,eid);
        ResultSet result = statement.executeQuery();
        boolean exists = false;
        if(result.next())
            exists = true;
        statement.close();
        connection.close();
        return exists;
    }

    public Map<String, byte[]> getUsersAndTemplate() throws SQLException {
        Map<String, byte[]> users = new HashMap<>();

        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("select eid, fingerprint from sakai_user_fingerprint");
        ResultSet result = statement.executeQuery();

        while(result.next()){
            String user = result.getString("eid");
            Blob blob = result.getBlob("finger");
            users.put(user,blob.getBytes(1,(int)blob.length()));
        }

        result.close();
        statement.close();
        connection.close();
        return users;
    }

    public byte[] getTemplate(String eid) throws SQLException {
        byte[] template = null;
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("select eid, fingerprint from sakai_user_fingerprint where eid = ?");
        statement.setString(1,eid);
        ResultSet result = statement.executeQuery();

        if(result.next()){
            Blob blob = result.getBlob("fingerprint");
            template = blob.getBytes(1,(int)blob.length());
        }

        result.close();
        statement.close();
        connection.close();

        return template;
    }
}
