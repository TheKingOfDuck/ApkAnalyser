# ApkAnalyser

一键提取安卓应用中可能存在的敏感信息。

Windows:[releases](https://github.com/TheKingOfDuck/ApkAnalyser/releases/download/1.0/apkAnalyser.zip)

✔️即兴开发，Enjoy it~~


![](https://blog.gzsec.org/post-images/1582291987982.png)

目前提取了APK内:
* 所有字符串
* 所有URLs
* 所有ip
* 可能是hash值的字符串
* 存在的敏感词（如oss.aliyun）
* 可能是accessKey的值
  
  使用Python开发，依赖于apkutils模块，可执行文件使用pyinstaller打包。
