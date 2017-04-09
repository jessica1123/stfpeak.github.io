---
layout:     post
title:      "Use Xposed To Hook"
subtitle:   "利用Xposed hook 制作程序钩子"
date:       2017-04-09 21:30:00 -0800
author:     "Dafeng"
header-img: "img/post-bg-universe.jpg"
header-mask: 0.3
catalog: true
tags:
    - Android
    - Xposed
    - Hook
---

# Xposed 简介

## **Xposed做法：**

Xposed是通过hook方法的方式来实现，由于Xposed修改了系统在启动时加载的Zygote进程相关的逻辑以及加载的资源(并且所有应用的启动都是从Zygote进程中拷贝出来的)，因此几乎可以架空一切安全，做所有事情，包括修改系统行为。

## **hook的大概原理：**

hook方法是 XposedBridge 中的一个私有native方法 hookMethodNative 改变被hook方法的类型为native并且link方法实现到它自己的native方法中，并且对调用者透明，该native方法调用XposedBridge中的 handleHookedMethod 方法，将参数， this 引用等传进来，之后在回调回去，这样我们就可以在方法执行前后做任何的事情了。

# Xposed 组件
## Xposed包含如下几个工程：

1. **XposedInstaller**，这是Xposed的插件管理和功能控制APP，也就是说Xposed整体管控功能就是由这个APP来完成的，它包括启用Xposed插件功能，下载和启用指定插件APP，还可以禁用Xposed插件功能等。注意，这个app要正常无误得运行必须能拿到root权限。
2. **Xposed**，这个项目属于Xposed框架，其实它就是单独搞了一套xposed版的zygote。这个zygote会替换系统原生的zygote。所以，它需要由XposedInstaller在root之后放到/system/bin下。
3. **XposedBridge**，这个项目也是Xposed框架，它属于Xposed框架的Java部分，编译出来是一个XposedBridge.jar包。
4. **XposedTools**，Xposed和XposedBridge编译依赖于Android源码，而且还有一些定制化的东西。所以XposedTools就是用来帮助我们编译Xposed和XposedBridge的。


# Xposed 安装
> 网上有很多中安装方法，在这里我们直接采取最简单的方法安装，直接打开应用市场（如：豌豆荚），搜索xPosed就会看见Xposed框架。

# Xposed开发
## Android Studio 开发步骤
### 1. 新建一个空安卓项目（带有activity也行）

### 2. 在 AndroidManifest.xml中通过 meta-data 申明:
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.dafeng.testforxposed">

        <application
            android:allowBackup="true"
            android:icon="@mipmap/ic_launcher"
            android:label="@string/app_name"
            android:supportsRtl="true"
            android:theme="@style/AppTheme">
            <activity
                android:name=".MainActivity"
                android:label="@string/app_name"
                android:theme="@style/AppTheme.NoActionBar">
                <intent-filter>
                    <action android:name="android.intent.action.MAIN" />

                    <category android:name="android.intent.category.LAUNCHER" />
                </intent-filter>
            </activity>


            <!-- 1、标识自己是否为一个Xposed模块 -->
            <meta-data
                android:name="xposedmodule"
                android:value="true"/>

            <!-- 2、Xposed模块的描述信息 -->
            <meta-data
                android:name="xposeddescription"
                android:value="a sample for xposed"/>

            <!-- 3、支持Xposed框架的最低版本 -->
            <meta-data
                android:name="xposedminversion"
                android:value="82"/>
        </application>

    </manifest>

### 3. 在app／build.gradle中添加
    provided 'de.robv.android.xposed:api:[latest version]'
    provided 'de.robv.android.xposed:api:[latest version]:sources'

    eg:
    dependencies {
    compile fileTree(dir: 'libs', include: ['*.jar'])
    androidTestCompile('com.android.support.test.espresso:espresso-core:2.2.2', {
        exclude group: 'com.android.support', module: 'support-annotations'
    })

    provided 'de.robv.android.xposed:api:82'
    provided 'de.robv.android.xposed:api:82:sources'

    compile 'com.android.support:appcompat-v7:24.2.1'
    compile 'com.android.support.constraint:constraint-layout:1.0.0-alpha8'
    compile 'com.android.support:design:24.2.1'
    testCompile 'junit:junit:4.12'
    }

    说明：
    1. 请留意，这个82是Xposed Framework API的版本号，叫做xposedminversion。
    2. xposedminversion可以在这里进行查询：
    https://bintray.com/rovo89/de.robv.android.xposed/api
    3. Xposed Framework API文档请参考：http://api.xposed.info/reference/packages.html

### 4. 模块实现
```java
package de.robv.android.xposed.mods.tutorial;

import de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Tutorial implements IXposedHookLoadPackage {
public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
    if (!lpparam.packageName.equals("com.android.systemui"))
        return;

    findAndHookMethod("com.android.systemui.statusbar.policy.Clock", lpparam.classLoader, "updateClock", new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            // this will be called before the clock was updated by the original method
        }
        @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            // this will be called after the clock was updated by the original method
        }
        });
    }
}
```
> beforeHookedMethod/afterHookedMethod会在被Hook函数之前/之后执行。


### 5. 添加Hook类的索引
1. 在assets目录下创建一个空文件，命名为xposed_init；
2. 在xposed_init中添加Hook类名：com.example.xposedtest.Tutorial




# 代码结构（示例）

```java
package cn.wjdiankong.xposedhook;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import android.location.GpsStatus;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.util.Log;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class GPSHooker implements IXposedHookLoadPackage{

    private final String TAG = "Xposed";
    private LoadPackageParam mLpp;

    public void log(String s){
        Log.d(TAG, s);
        XposedBridge.log(s);
    }

    //不带参数的方法拦截
    private void hook_method(String className, ClassLoader classLoader, String methodName,
            Object... parameterTypesAndCallback){
        try {
            XposedHelpers.findAndHookMethod(className, classLoader, methodName, parameterTypesAndCallback);
        } catch (Exception e) {
            XposedBridge.log(e);
        }
    }

    //带参数的方法拦截
    private void hook_methods(String className, String methodName, XC_MethodHook xmh){
        try {
            Class<?> clazz = Class.forName(className);
            for (Method method : clazz.getDeclaredMethods())
                if (method.getName().equals(methodName)
                        && !Modifier.isAbstract(method.getModifiers())
                        && Modifier.isPublic(method.getModifiers())) {
                    XposedBridge.hookMethod(method, xmh);
                }
        } catch (Exception e) {
            XposedBridge.log(e);
        }
    }


    @Override
    public void handleLoadPackage(LoadPackageParam lpp) throws Throwable {
        mLpp = lpp;

        hook_method("android.net.wifi.WifiManager", mLpp.classLoader, "getScanResults",
                new XC_MethodHook(){
            /**
             * Android提供了基于网络的定位服务和基于卫星的定位服务两种
             * android.net.wifi.WifiManager的getScanResults方法
             * Return the results of the latest access point scan.
             * @return the list of access points found in the most recent scan.
             */
            @Override
            protected void afterHookedMethod(MethodHookParam param)
                    throws Throwable {
            	//返回空，就强制让apps使用gps定位信息
                param.setResult(null);
            }
        });

        hook_method("android.telephony.TelephonyManager", mLpp.classLoader, "getCellLocation",
                new XC_MethodHook(){
            /**
             * android.telephony.TelephonyManager的getCellLocation方法
             * Returns the current location of the device.
             * Return null if current location is not available.
             */
            @Override
            protected void afterHookedMethod(MethodHookParam param)
                    throws Throwable {
                param.setResult(null);
            }
        });

        hook_method("android.telephony.TelephonyManager", mLpp.classLoader, "getNeighboringCellInfo",
                new XC_MethodHook(){
            /**
             * android.telephony.TelephonyManager类的getNeighboringCellInfo方法
             * Returns the neighboring cell information of the device.
             */
            @Override
            protected void afterHookedMethod(MethodHookParam param)
                    throws Throwable {
                param.setResult(null);
            }
        });

        hook_methods("android.location.LocationManager", "requestLocationUpdates",
                new XC_MethodHook() {
            /**
             * android.location.LocationManager类的requestLocationUpdates方法
             * 其参数有4个：
             * String provider, long minTime, float minDistance,LocationListener listener
             * Register for location updates using the named provider, and a pending intent
             */
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                if (param.args.length == 4 && (param.args[0] instanceof String)) {
                    //位置监听器,当位置改变时会触发onLocationChanged方法
                    LocationListener ll = (LocationListener)param.args[3];

                    Class<?> clazz = LocationListener.class;
                    Method m = null;
                    for (Method method : clazz.getDeclaredMethods()) {
                        if (method.getName().equals("onLocationChanged")) {
                            m = method;
                            break;
                        }
                    }

                    try {
                        if (m != null) {
                            Object[] args = new Object[1];
                            Location l = new Location(LocationManager.GPS_PROVIDER);
                            //台北经纬度:121.53407,25.077796
                            double la=121.53407;
                            double lo=25.077796;
                            l.setLatitude(la);
                            l.setLongitude(lo);
                            args[0] = l;
                            m.invoke(ll, args);
                            XposedBridge.log("fake location: " + la + ", " + lo);
                        }
                    } catch (Exception e) {
                        XposedBridge.log(e);
                    }
                }
            }
        });


        hook_methods("android.location.LocationManager", "getGpsStatus",
                new XC_MethodHook(){
            /**
             * android.location.LocationManager类的getGpsStatus方法
             * 其参数只有1个：GpsStatus status
             * Retrieves information about the current status of the GPS engine.
             * This should only be called from the {@link GpsStatus.Listener#onGpsStatusChanged}
             * callback to ensure that the data is copied atomically.
             *
             */
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                GpsStatus gss = (GpsStatus)param.getResult();
                if (gss == null)
                    return;

                Class<?> clazz = GpsStatus.class;
                Method m = null;
                for (Method method : clazz.getDeclaredMethods()) {
                    if (method.getName().equals("setStatus")) {
                        if (method.getParameterTypes().length > 1) {
                            m = method;
                            break;
                        }
                    }
                }
                m.setAccessible(true);
                //make the apps belive GPS works fine now
                int svCount = 5;
                int[] prns = {1, 2, 3, 4, 5};
                float[] snrs = {0, 0, 0, 0, 0};
                float[] elevations = {0, 0, 0, 0, 0};
                float[] azimuths = {0, 0, 0, 0, 0};
                int ephemerisMask = 0x1f;
                int almanacMask = 0x1f;
                //5 satellites are fixed
                int usedInFixMask = 0x1f;
                try {
                    if (m != null) {
                        m.invoke(gss,svCount, prns, snrs, elevations, azimuths, ephemerisMask, almanacMask, usedInFixMask);
                        param.setResult(gss);
                    }
                } catch (Exception e) {
                    XposedBridge.log(e);
                }
            }
        });
    }

}


```
