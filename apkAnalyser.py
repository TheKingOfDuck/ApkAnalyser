# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     fileMonitor
   Description :
   Author :       CoolCat
   date：          2019/1/3
-------------------------------------------------
   Change Activity:
                   2019/1/3:
-------------------------------------------------
"""
__author__ = 'CoolCat'

import os
import sys
import re
import binascii
import base64
import datetime
from apkutils import APK
import json
import operator

def banner():
    print(""" 
             _                          _                     
            | |       /\               | |                    
  __ _ _ __ | | __   /  \   _ __   __ _| |_   _ ___  ___ _ __ 
 / _` | '_ \| |/ /  / /\ \ | '_ \ / _` | | | | / __|/ _ \ '__|
| (_| | |_) |   <  / ____ \| | | | (_| | | |_| \__ \  __/ |   
 \__,_| .__/|_|\_\/_/    \_\_| |_|\__,_|_|\__, |___/\___|_|   
      | |    Code By CoolCat               __/ |              
      |_|https://github.com/TheKingOfDuck |___/  
          """)

def getManifestInfo(apk):

    """
    :param apk: apk对象
    :return ManifestInfo: AndroidManifest.xml中的字符串信息
    """

    if apk.get_manifest():
        manifestInfo = json.dumps(apk.get_manifest(), indent=1)
        print("\tPackage: {}\tVersion: {}\n\tMainActivity: {}".format(apk.get_manifest()['@package'],
                                                                  apk.get_manifest()['@android:versionName'],
                                                                  apk.get_manifest()['application']['@android:name'],
                                                                  ))
    elif apk.get_org_manifest():
        manifestInfo = apk.get_org_manifest()
        print("\tPackage: {}\tVersion: {}\n\tMainActivity: {}".format(apk.get_manifest()['@package'],
                                                                  apk.get_manifest()['@android:versionName'],
                                                                  apk.get_manifest()['application']['@android:name'],
                                                                  ))
    return manifestInfo

def getSignInfo(apk):

    """
    :param apk: apk对象
    :return: apk签名者的基本信息
    """

    for item in apk.get_certs():
        sign = "\tSigner:\t{}".format(item[0])
        print(sign)
        return sign

def getStrings(apk):

    """
    :param apk: apk对象
    :return strings:处理后APK中所有的字符串信息
    """

    stringList = []

    for item in apk.get_strings():
        string = binascii.unhexlify(item).decode(errors='ignore')
        if string not in stringList:
            stringList.append(string)

    return stringList

def isBase64(string):
    try:
        missing_padding = 4 - len(string) % 4
        if missing_padding:
            string += '=' * missing_padding
        # print(base64.b64decode(string))
        # print(type(base64.b64decode(string)))
        return True
    except:
        pass
    return False

def dex2jar(apkPath,savePath):
    """
    解压APK并将dex转为jar
    :return: bool
    """
    from shutil import move as moveFile
    from zipfile import ZipFile as unzip
    from os import popen as cmd


    try:
        z = unzip(apkPath, 'r')
        z.extractall(path=r"{}/files/".format(savePath))
        z.close()




        os.cmd(".\dex2jar\d2j-dex2jar --force ./{}/files/classes.dex".format(savePath))
        if os.path.exists("classes-dex2jar.jar"):
            moveFile("classes-dex2jar.jar", "./{}/{}.jar".format(savePath,apkFile))
            return True
    except Exception as e:
        # print(e)
        pass
    return False

def do_unique(full_list):
    # 如果还有误报,将误报的字符串加入下面列表中即可.
    exclude_str = ["get", "and", "set", "config", "create", "access", "is", "check", "load", "class", "method", "function",
               "zone", "sha", "des", "aes", "rsa", "dsa", "can", "clear", "long", "task", "thread", "process", "api",
               "async", "sync", "size", "tag", "uuid", "impl", "int", "parser", "conf", "param", "rate", "audio",
               "push", "short", "full", "byte", "state", "info", "util", "java", "cert", "sign", "req", "with", "for",
               "cons", "data", "password", "open", "close", "calc", "code", "track", "group", "time"
               ]
    result = []

    for a in range(0, len(full_list)):
        res = []
        # print(a, end='\t')
        for ex in exclude_str:
            res.append(operator.contains(full_list[a].lower(), ex))
        if len(set(res)) == 1:
            print(full_list[a])
            result.append(full_list[a])
    return result

def main(apkPath):

    starttime = datetime.datetime.now()

    """
    :param apkPath: apk文件的最终路径
    :return: NULL
    """

    print("[?]Analyzing {}".format(apkPath))

    if "/" in apkPath:
        savePath = "./result/" + apkPath.split("/")[-1].split(".")[0]
    else:
        savePath = "./result/" + apkPath.split(".")[0]
    try:
        os.mkdir(savePath)
    except Exception as e:
        # print(e)
        pass

    if dex2jar(apkPath,savePath):
        print("[+]Dex2jar success!")

    # print(savePath)

    '''
    先判断这个安装包是否提取过，再开始处理。
    '''
    if len([lists for lists in os.listdir(savePath) if os.path.isfile(os.path.join(savePath, lists))]) > 5:
        print("[!]The information has been extracted to {}. Please delete it if you need to extract it again".format(savePath))
    else:
        apk = APK(apkPath)

        #获取AndroidManifest.xml的字符串信息
        manifestInfo = getManifestInfo(apk)
        xml = open("{}/AndroidManifest.xml".format(savePath),"w")
        xml.write(manifestInfo)
        xml.close()

        #签名信息
        sign = getSignInfo(apk)

        print("[?]Extracting all strings in apk")

        stringList = getStrings(apk)

        try:
            urlList = []
            ipList = []
            hashlist = []
            forbidStrList = []
            accessKeyList = []

            for string in stringList:

                # 保存所有的字符串
                base = open("{}/strings.txt".format(savePath), "a")
                try:
                    base.write(str(string) + '\n')
                except Exception as e:
                    # print(e)
                    pass
                base.close()

                '''
                下面开始提取URLs
                '''
                # url = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', string)

                urlStrList = ["https://", "http://"]  # 提取的特征
                for urlStr in urlStrList:
                    if urlStr in string:
                        # print(string)
                        if string not in urlList:
                            u = open("{}/urls.txt".format(savePath), "a")
                            u.write(str(string) + '\n')
                            u.close()
                            urlList.append(string)

                '''
                判断是否包含IP
                '''
                p = re.compile(
                    '(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)')
                if p.match(string):
                    ip = open("{}/ips.txt".format(savePath), "a")
                    ip.write(str(string) + '\n')
                    ip.close()
                    if string not in ipList:
                        ipList.append(string)

                '''
                下面开始提取可能是base64编码以及hash的值
                '''

                '''
                下面开始匹配32位长度和15长度的hash
                '''
                if len(string) == 32 or len(string) == 16:
                    if re.match(r'^[a-z0-9]{16,32}$', string):
                        if string not in hashlist:
                            hashlist.append(string)
                            hashs = open("{}/hash.txt".format(savePath), "a")
                            hashs.write(str(string) + '\n')
                            hashs.close()

                '''
                下面提取可能存在的敏感字符串
                '''
                # forbidStr = ["accessKey", "database","ssh","rdp","smb","mysql","sqlserver","oracle",
                #              "ftp","mongodb","memcached","postgresql","telnet","smtp","pop3","imap",
                #              "vnc","redis","admin","root","config","jdbc",".properties","aliyuncs",
                #              "oss"]  # 特征字典
                forbidStr = ['accesskey', 'aliyuncs']
                for forbid in forbidStr:
                    if forbid in string:
                        # print(string)
                        if string not in forbidStrList:
                            fb = open("{}/forbidStr.txt".format(savePath), "a")
                            try:
                                fb.write(str(string) + '\n')
                            except Exception as e:
                                print(e)
                                pass
                            fb.close()
                            forbidStrList.append(string)

                '''
                下面开始匹配AccessKey,自己测试发现:        
                AccessKeyId 约为24位
                AccessKeySecret 约为30位
                '''

                if str(string).isalnum():
                    if re.match(r'^(?:(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])).{24,24}$', string):# or re.match(r'^(?:(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])).{16,16}$', string):
                        if string not in accessKeyList:
                            accessKeyList.append(string)

                    if re.match(r'^(?:(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])).{30,30}$', string):
                        if string not in accessKeyList:
                            accessKeyList.append(string)
                            
        except Exception as e:
            #print(e)
            pass
        
        # 提升阿里云AK检测正确率
        for ak_str in do_unique(accessKeyList):
            ak = open("{}/accessKey.txt".format(savePath), "a")
            if ak_str.startswith("LTAI"):
                ak.write("=============AccessKeyId================\n")
                ak.write("Id:{}\n".format(str(ak_str)))
            else:
                ak.write("Id:{}\n".format(str(ak_str)))
            ak.close()

        print("""[*]Found:
        \tString:{}\tURL:{}
        \tIps:{}\tHash:{}\tForbidStr:{}
        \tMaybe it's accessKey:{}""".format(len(stringList),len(urlList),len(ipList),
                                            len(hashlist),len(forbidStrList),len(accessKeyList))
              )

    endtime = datetime.datetime.now()
    print("[+]Use time {}s\n".format((endtime - starttime).seconds))


if __name__ == '__main__':


    if os.path.isdir('result') == False:
        os.mkdir('result')
    if os.path.isdir('apps') == False:
        os.mkdir('apps')

    banner()


    print(datetime.datetime.now().strftime("[+]%Y-%m-%d %H:%M:%S running"))

    """
    处理参数:
        需要兼容Windows和macOS,所以判断写得比较多。
    """
    if len(sys.argv) > 1:
        for num in range(1,len(sys.argv)):
            print("[?]{}".format(sys.argv[num]))
            if os.path.exists(sys.argv[num]):
                apkPath = str(sys.argv[num]).replace("\\", "/")
                if str(apkPath).endswith(".apk"):
                    if os.path.exists(apkPath):
                        main(apkPath)
    elif os.path.exists("apps"):
        print("[+]Traversing APK files")
        for (dirPath,dirNames,fileNames) in os.walk(os.path.abspath("apps" + os.curdir)):
            if len(fileNames) > 0:
                for apkFile in fileNames:
                    if os.path.splitext(apkFile)[1] == '.apk':
                        apkPath = "apps/" + apkFile
                        try:
                            main(apkPath)
                        except:pass
            else:
                print("Pls put all APK files in the apps folder")

    else:
        os.mkdir("apps")

        if str(sys.argv[0]).endswith(".exe"):
            print(
                "\tTry Command \"{} test.apk /Users/CoolCat/test.apk\"\n\tOr put all APK files in the apps folder".format(
                    sys.argv[0]))
        else:
            print(
                "\tTry Command \"python3 {} test.apk /Users/CoolCat/test.apk\"\n\tOr put all APK files in the apps folder".format(
                    sys.argv[0]))

    print(datetime.datetime.now().strftime("[+]%Y-%m-%d %H:%M:%S end\n\t Feedback bug: https://github.com/TheKingOfDuck"))

