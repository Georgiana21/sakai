package org.sakaiproject.util;

import com.mysql.jdbc.jdbc2.optional.MysqlDataSource;
import javafx.util.Pair;

import javax.sql.rowset.serial.SerialBlob;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.*;
import java.util.*;

public class DatabaseHelper {

    private static DatabaseHelper instance;
    private MysqlDataSource dataSource;
    private static Properties props;

    private DatabaseHelper(){
        props = new Properties();
        try {
            props.load(new FileInputStream(System.getProperty("sakai.home") + "\\" + "sakai.properties"));
            dataSource = new MysqlDataSource();
            dataSource.setURL(getOrBail("url@javax.sql.BaseDataSource"));
            dataSource.setUser(getOrBail("username@javax.sql.BaseDataSource"));
            dataSource.setPassword(getOrBail("password@javax.sql.BaseDataSource"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static DatabaseHelper getInstance(){
        if(instance == null)
            instance = new DatabaseHelper();
        return instance;
    }

    private static String getOrBail(String property) {
        String value = props.getProperty(property);
        if (value == null) {
            throw new IllegalStateException("Unable to find configuration for: "+ property);
        }
        return value;
    }

    public void saveUser(String username, byte[] template,int size) throws SQLException {
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("insert into sakai_user_fingerprint(eid,fingerprint,template_size) values(?,?,?) on duplicate key update fingerprint = ?, template_size=?");
        statement.setString(1,username);
        Blob blob = new SerialBlob(template);
        statement.setBlob(2, blob);
        statement.setInt(3,size);
        statement.setBlob(4,blob);
        statement.setInt(5,size);
        statement.executeUpdate();
        statement.close();
        connection.close();
    }

    public void saveConsent(String username, String consentStatement) throws SQLException {
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("insert into sakai_data_consent(eid, consent_statement) values(?,?)  on duplicate key update consent_statement = ?");
        statement.setString(1,username);
        statement.setString(2,consentStatement);
        statement.setString(3,consentStatement);
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

    public Map<String, Pair<byte[],Integer>> getUsersAndTemplate() throws SQLException {
        Map<String, Pair<byte[],Integer>> users = new HashMap<>();

        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("select eid, fingerprint, template_size from sakai_user_fingerprint");
        ResultSet result = statement.executeQuery();

        while(result.next()){
            String user = result.getString("eid");
            Blob blob = result.getBlob("fingerprint");
            users.put(user, new Pair<byte[], Integer>(blob.getBytes(1,(int)blob.length()),result.getInt("template_size")));
        }

        result.close();
        statement.close();
        connection.close();
        return users;
    }

        public Pair<byte[],Integer> getTemplate(String eid) throws SQLException {
        byte[] template = null;
        int size = 0;
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("select eid, fingerprint, template_size from sakai_user_fingerprint where eid = ?");
        statement.setString(1,eid);
        ResultSet result = statement.executeQuery();

        if(result.next()){
            Blob blob = result.getBlob("fingerprint");
            template = blob.getBytes(1,(int)blob.length());
            size = result.getInt("template_size");
        }

        result.close();
        statement.close();
        connection.close();

        return new Pair<byte[], Integer>(template, size);
    }

    public void saveCode(String username, String code) throws SQLException {
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("insert into sakai_user_code_map(eid,code) values(?,?) on duplicate key update code = ?, timestamp = CURRENT_TIMESTAMP ");
        statement.setString(1,username);
        statement.setString(2,code);
        statement.setString(3,code);
        statement.executeUpdate();
        statement.close();
        connection.close();
    }

    public void deleteCodeEntryForUser(String eid) throws SQLException {
        Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("delete from sakai_user_code_map where eid = ? ");
        statement.setString(1,eid);
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
