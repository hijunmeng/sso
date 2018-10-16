package com.example.authorize.util;

import org.slf4j.LoggerFactory;

public class Log {

    public static String perfix = "############## ";

    public static void error(String msg) {
        LoggerFactory.getLogger(getClassName()).error(perfix + msg);
    }

    public static void error(String msg, Object... obj) {
        LoggerFactory.getLogger(getClassName()).error(perfix + msg, obj);
    }


    public static void warn(String msg) {
        LoggerFactory.getLogger(getClassName()).error(perfix + msg);
    }

    public static void warn(String msg, Object... obj) {
        LoggerFactory.getLogger(getClassName()).error(perfix + msg, obj);
    }


    public static void info(String msg) {
        LoggerFactory.getLogger(getClassName()).info(perfix + msg);
    }

    public static void info(String msg, Object... obj) {
        LoggerFactory.getLogger(getClassName()).info(perfix + msg, obj);
    }

    public static void debug(String msg) {
        LoggerFactory.getLogger(getClassName()).debug(perfix + msg);
    }

    public static void debug(String msg, Object... obj) {
        LoggerFactory.getLogger(getClassName()).debug(perfix + msg, obj);
    }


    private static String getClassName() {
        return new SecurityManager() {
            public String getClassName() {
                return getClassContext()[3].getName();
            }
        }.getClassName();
    }

}
