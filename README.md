# ApkAnalyser

一键提取安卓应用中可能存在的敏感信息。

* 20200304
  
  修复“apkPath is not defined”，参数带进来的路径忘记赋值直接写了...

Windows:[releases](https://github.com/TheKingOfDuck/ApkAnalyser/releases/download/1.0/apkAnalyser.zip)

✔️即兴开发，Enjoy it~~

### 用法

* 懒人做法，将所有app放到程序自动创建的apps目录，再运行主程序就好了，不用加参数。

### 功能
目前提取了APK内:
* 所有字符串
* 所有URLs
* 所有ip
* 可能是hash值的字符串
* 存在的敏感词（如oss.aliyun）
* 可能是accessKey的值

![](https://blog.gzsec.org/post-images/1582291987982.png)

  
  使用Python开发，依赖于apkutils模块，可执行文件使用pyinstaller打包。
