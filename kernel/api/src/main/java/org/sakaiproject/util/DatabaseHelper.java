package org.sakaiproject.util;

import com.mysql.jdbc.jdbc2.optional.MysqlDataSource;
import javafx.util.Pair;

import javax.sql.rowset.serial.SerialBlob;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
        PreparedStatement statement = connection.prepareStatement("insert into sakai_user_fingerprint(eid,fingerprint) values(?,?) on duplicate key update fingerprint = ?");
        statement.setString(1,username);
        Blob blob = new SerialBlob(template);
        statement.setBlob(2, blob);
        statement.setBlob(3,blob);
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
            Blob blob = result.getBlob("fingerprint");
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

    public void saveCode(String username, String code) throws SQLException {
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("insert into sakai_user_code_map(eid,code) values(?,?) on duplicate key update code = ?");
        statement.setString(1,username);
        statement.setString(2,code);
        statement.setString(3,code);
        statement.executeUpdate();
        statement.close();
        connection.close();
    }

    public List<String> getCodes() throws SQLException {
        List<String> codes = new ArrayList<>();
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("select code from sakai_user_code_map");
        ResultSet result = statement.executeQuery();
        while (result.next())
            codes.add(result.getString("code"));
        statement.close();
        connection.close();
        return codes;
    }

    public Pair<String, Timestamp> getEidAndTimestamp(String code) throws SQLException {
        String eid = "";
        Timestamp timestamp = null;
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("select eid, timestamp from sakai_user_code_map where code=upper(?)");
        statement.setString(1,code);
        ResultSet result = statement.executeQuery();
        if(result.next()){
            eid = result.getString("eid");
            timestamp = result.getTimestamp("timestamp");
        }
        statement.close();
        connection.close();
        return new Pair<>(eid,timestamp);
    }
}
