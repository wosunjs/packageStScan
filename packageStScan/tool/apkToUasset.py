import os
import sys
import time
import zipfile
import shutil

def print_help():
    print(r"Usage:py apkToUasset.py <apk_path> / py apkToUasset.py <uasset_path> [ue_version, default:4.18]")
    print(r"Example: apkToUasset.py .\test.apk")
    print(r"Example: apkToUasset.py .\test.uasset")
    print(r"Example: apkToUasset.py .\test.uasset 4.18")
    print("the folder or json file will be created in the directory")
    print("use this script please install apktool first!")
    exit(0)

def uassetToJson(uasset_path, ue_version):
    # 在uasset文件路径下解析为.json文件
    uasset_path = os.path.abspath(uasset_path)
    file_name = os.path.basename(uasset_path)
    file_name = file_name.split(".")[0]
    json_path = os.path.dirname(uasset_path)
    json_path = os.path.join(json_path, file_name + ".json")
    # 组合执行解析uasset文件指令
    cmd = r"uassetParseBase\uassetParseBase.exe" + " " + uasset_path + " " + json_path + " " + ue_version
    os.system(cmd)

if __name__ == "__main__":
    # 打印所有参数
    if len(sys.argv) < 2 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
        print_help()

    # 获取apk文件名，并在其路径下创建对应文件夹
    apk_path = sys.argv[1]
    #apk_path = r"C:\Users\anankeliu\Desktop\android_packing_test\widgetTest\Android_Multi\test2-armv7-es2.apk"
    # 如果apk文件后缀不正确，则提示用户
    if not apk_path.endswith(".apk") and not apk_path.endswith(".uasset"):
        print("The file is not apk or uasset, please check it")
        exit(0)

    # 如果是uasset文件则解析为json
    if apk_path.endswith(".uasset"):
        if len(sys.argv) == 3:
            ue_version = sys.argv[2]
        else:
            ue_version = "4.18"
        uassetToJson(apk_path, ue_version)
        exit(0)

    # 如果是apk文件则提取content
    apk_name = os.path.basename(apk_path)
    apk_name = apk_name.split(".")[0]
    apk_path = os.path.abspath(apk_path)
    folder_path = os.path.dirname(apk_path)
    res_path = os.path.join(folder_path, apk_name + "-res")
    res_content_path = os.path.join(folder_path, apk_name + "-content")
    folder_path = os.path.join(folder_path, apk_name)
    uasset_unzip_path = os.path.join(folder_path, apk_name + "-uasset")

    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
    if not os.path.exists(res_path):
        os.mkdir(res_path)
    if not os.path.exists(uasset_unzip_path):
        os.mkdir(uasset_unzip_path)
    if not os.path.exists(res_content_path):
        os.mkdir(res_content_path)
    
    # 解压apk文件

    os.system("apktool d -f -o " + folder_path + " " + apk_path)
    print("apk unpack complete!")

    # 获取obb文件路径
    obb_path = os.path.join(folder_path, "assets", "main.obb.png")

    # 使用zipfile模块解压obb文件
    with zipfile.ZipFile(obb_path, "r") as zip_ref:
        zip_ref.extractall(uasset_unzip_path)
    print("obb unpack complete!")

    # 获取pak路径
    # 在uasset_unzip_path路径下递归搜索pak文件
    for root, dirs, files in os.walk(uasset_unzip_path):
        for file in files:
            if file.endswith(".pak"):
                pak_path = os.path.join(root, file)
                break
    
    # 使用unrealpak.exe解压pak文件
    os.system(r".\UnrealPak4.18\UnrealPak.exe " + pak_path + " -Extract " + res_path)
    print("pak unpack complete!")

    # 删除apktool生成的文件夹
    #os.system("rmdir /s /q " + folder_path)

    # 找到res_path中名为Content的文件夹
    for root, dirs, files in os.walk(res_path):
        for dir in dirs:
            if dir == "Content":
                content_path = os.path.join(root, dir)
                break

    # 将Content文件夹移动到res_content_path路径下
    shutil.move(content_path, res_content_path + str(int(time.time())) )

    # 删除res_path
    #os.system("rmdir /s /q " + res_path)