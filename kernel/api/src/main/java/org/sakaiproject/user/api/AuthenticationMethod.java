package org.sakaiproject.user.api;

public enum AuthenticationMethod {
    PASSWORD("Password"), CODE("Code");

    String value;

    AuthenticationMethod(String value)
    {
        this.value = value;
    }

    public String getValue()
    {
        return value;
    }
}
