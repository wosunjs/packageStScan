# 随机生成二进制文件
import os
import sys
import time
import random

# 文件大小设置为2MB
file_size = 2 * 1024 * 1024
# 中文测试字符字典
zh_dict = {"测试" : 0, "我" : 0, "要" : 0, "试一试" : 0}
# 英文字符串字典
en_dict = {"test" : 0, "have" : 0, "zh": 0, "Chinese" : 0, "a" : 0}
# 符号字典
sym_dict = {":" : 0, "," : 0, " " : 0, "!" : 0, "," : 0 }
# 数字字典
num_dict = {"1" : 0, "2" : 0, "3" : 0, "4" : 0, "5" : 0, "6" : 0, "7" : 0, "8" : 0, "9" : 0, "0" : 0}

# 记录随机放入的中文字符串个数
zh_str_num = 0

def get_zh_string():
    zh_str = ""
    # 以25%的概率选择每一个字典元素
    for key in zh_dict.keys():
        if random.random() < 0.25:
            zh_str += key
            zh_dict[key] += 1
    if zh_str == "":
        # 以轮盘赌的方式再次尝试
        zh_str = get_zh_string()

    # 以每段英文4%的概率附加英文字符串
    for key in en_dict.keys():
        if random.random() < 0.04:
            zh_str += key
            en_dict[key] += 1
    # 以2%的概率附加数字
    for key in en_dict.keys():
        if random.random() < 0.02:
            zh_str += key
    
    # 以60%的概率停止
    if random.random() < 0.6:
        return zh_str
    else:
        return zh_str + get_zh_string()

    
def get_en_string():
    res_str = ""
    # 以20%的概率选择每一个字典元素
    for key in en_dict.keys():
        if random.random() < 0.2:
            res_str += key
            en_dict[key] += 1
    # 以30%的概率附加数字
    for key in en_dict.keys():
        if random.random() < 0.03:
            res_str += key
    # 以60%的概率停止
    if random.random() < 0.6:
        return res_str
    else:
        return res_str + get_en_string()

def main():
    # 使用时间更新种子
    random.seed(time.time())
    global zh_str_num
    # 打开一个用户输入的文件
    file_path = r"C:\Users\anankeliu\Desktop\uassetParse\temp\eflTest.so"
    # 打开文件
    with open(file_path, "wb") as file:
        while file.tell() < file_size:
            # 以5%的概率插入字符串
            if random.random() < 0.05:
                # 以1%的概率写入中文字符串
                if random.random() < 0.2:
                    res_str = get_zh_string()
                    file.write(res_str.encode("utf-8") + b'\0') # 写入一个"\0"字节模拟c++的字符串结尾
                    zh_str_num += 1
                else:
                    res_str = get_en_string()
                    file.write(res_str.encode("ascii") + b'\0') # 写入一个"\0"字节模拟c++的字符串结尾
            else:
                # 其他情况下，写入10个随机字节
                file.write(os.urandom(10))

    # 输出中文字符串总数
    print("文件大小: %d" % file_size)
    print("中文字符串总数: %d" % zh_str_num)
    # 输出中文字典key和对应的value
    for key in zh_dict.keys():
        print(key, zh_dict[key])

if __name__ == "__main__":
    main()