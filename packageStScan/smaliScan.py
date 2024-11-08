import os
import sys
import time
import json

import tool.parseHelper as PH

# 获取通用函数
check_file_exists = PH.check_file_exists
print_progress_bar = PH.print_progress_bar
setToString = PH.setToString
get_print_str_num = PH.get_print_str_num
scan_string_en = PH.scan_string_dict
scan_string_zh = PH.scan_string_zh
get_path = PH.get_path

class smaliScan(PH.BaseParse):
    def __init__(self, argv):
        super().__init__(argv)
        # 因smali文件不需要解析直接扫描，故不存在临时文件夹
        self.no_parse = True
        self.scan_report_path = os.path.join(os.getcwd(), "res\\smali_" + self.now_time + ".json")    # 报告保存文件夹临时为当前目录下的res文件夹

        # 填充扫描文件列表
        for root, dirs, files in os.walk(self.scan_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file in self.ignore_file_list or (self.ignore_file_paht != "" and self.ignore_file_paht in file_path):
                    continue
                if file.endswith(".smali"):
                    self.scan_file_list.add(file_path)
        # 获取文件数量
        self.file_count = len(self.scan_file_list)

    def print_help(self):
        print("------------------------------------------------------------------------------------------------------")
        print("Welcome to use smaliScan.py, a tool to scan smali files.Please choose the following usages:")
        print("Usage: smaliScan.py scan_folder_path [-choice]")
        print("-r [scan_path]: set the scan report file save path.")
        print("-d [dict_path]: set the dict file which is used for string scan.")
        print("-zh: open the switch to scan for hidden Chinese.")
        print("-h: this help message")
        print("......")
        print("------------------------------------------------------------------------------------------------------")
        exit(0)
    
    def parse_argv(self, argv):
        # 检测是否打印帮助信息
        if len(argv) < 2 or "-h" in argv or "--help" in argv:
            self.print_help()

        # 解析第一参数,获取扫描路径
        self.scan_folder_path = get_path(argv[1])

        # 解析后续选项
        if len(argv) > 2:
            for i in range(2, len(argv)):
                if argv[i] == "-r":
                    i += 1
                    self.scan_report_path = get_path(argv[i])
                if argv[i] == "-d":
                    i += 1
                    self.string_dict_path = get_path(argv[i])
                # 如果是-zh参数，则将is_scan_zh改为True，但目前默认扫描全开
                if argv[i] == "-zh":
                    self.is_scan_zh = True

    def do_scan(self):
        # 开始扫描
        print("--------------------------------------------------------------------------------------------------------------------------")
        print("Scan Info......")
        print("Scan folder path:", self.scan_folder_path)
        print("Scan report path:", self.scan_report_path)
        print("String dict path:", self.string_dict_path)
        print("Is scan Chinese:", self.is_scan_zh)
        print("...............")

        # 读取字典文件(@TODO：构建字典树)
        if self.string_dict_path != "" and os.path.exists(self.string_dict_path):
            print("Reading string dict......")
            # 使用一个集合，读取字典文件
            with open(self.string_dict_path, "r", encoding="utf-8") as f:
                strs = f.read()
                # 逐行读取字典文件内容
                for line in strs.split("\n"):
                    if line != "":
                        self.string_dict.add(line)
            print("Read done!")

        # 遍历smali文件，对其进行扫描
        print("Start Scanning smali......")
        start_time = time.time()
        # 对scan_report_path文件进行清空(新建)
        open(self.scan_report_path, "w", encoding="utf-8")
        # 开始扫描并写入报告
        self.scan_smali_folder()
        end_time = time.time()
        print("\nScan done! Use time:", end_time - start_time, "s")
        print("Scan file num:", self.file_count)
        print("--------------------------------------------------------------------------------------------------------------------------")

    def scan_smali_folder(self):
        file_scan_count = 0
        # 遍历待扫描smali文件
        for file in self.scan_file_list:
            # 扫描smali文件
            self.scan_smali_file(file)
            # 打印进度
            file_scan_count += 1
            print_progress_bar(file_scan_count, self.file_count, "Scanning smali file")
        

    def scan_smali_file(self, smali_file_path):
        # 获取报告字典
        scan_report = self.get_json_scan_dict(smali_file_path)

        # 读取smali文件并进行扫描
        with open(smali_file_path, "r", encoding="utf-8") as f:
            # 逐行读取smali文件内容
            lineId = 0  # 记录行号
            for line in f.readlines():
                # 获取行号作为key
                key = "line number:" + str(lineId)
                lineId += 1
                # 进行字符串字典扫描
                result_str = scan_string_en(line, self.string_dict)
                # 进行中文扫描(如果可能存在中文的话)
                have_zh = 0
                if "const-string" in line or '"' in line:   # 通过检测是否存在"来判断是否是注解 or 字符串值
                    # 进行中文扫描
                    have_zh = scan_string_zh(line)
                # 保留权重接口，因目前暂无很好的方法区分字符串字典扫描结果的精准性(smali字符串中存在中文不存在误判)
                if have_zh > 0 or len(result_str) > 0:
                    scan_report["weight:2"][key] = dict()
                    scan_report["weight:2"][key]["line_val"] = line
                    scan_report["weight:2"][key]["sen_str"] = setToString(result_str)
                    scan_report["weight:2"][key]["have_zh"] = have_zh > 0

        # 扫描为空则跳过写入该文件结果
        self.write_json_file(scan_report)
        return

    # 检查字符左侧是否是合法分隔
    def law_left(self, left, first):
        # 如果左侧为空格、数字、"_"、"."、""则合法
        if left == " " or left == "." or left == "_" or left == "" or left == "/" or left == "L" or left == ")" or left == ">" or left.isnumeric():
            return True
        # 如果左侧为汉字则合法
        if ("\u4e00" <= left <= "\u9fff"):
            return True
        # 如果左侧为小写字母,当前为大写字母则合法
        if left.isalpha() and left.islower() and first.isalpha() and first.isupper():
            return True
        # 都不是则不合法
        return False

    # 检查字符右侧是否是合法分隔
    def law_right(self, right, last):
        # 如果右侧为空格、数字、"_"、"."、""、"/"则合法
        if right == " " or right == "." or right == "_" or right == "" or right == "/" or right == ";" or right == "(" or right.isnumeric():
            return True
        # 如果右侧为汉字则合法
        if ("\u4e00" <= right <= "\u9fff"):
            return True
        # 如果右侧为大写字母,当前字母为小写字母则合法
        if right.isalpha() and right.isupper() and last.isalpha() and last.islower():
            return True
        # 都不是则不合法
        return False

    # 字符串字典扫描，返回一个集合，为其中包含的字典字符串
    def scan_string_dict(self, string_val, string_dict):
        # 将string_val转换成字符串,防止NoneType
        if type(string_val) != str:
            string_val = str(string_val)
        result = set()
        # 判断字符串是否为空or字典为空
        if string_val == "" or string_dict == dict():
            return result
        # 通过检测敏感字符串是否存在，并判断左右是否合法
        for string in string_dict:
            if string in string_val:
                # 获取字符串在string_val中的位置
                start = string_val.find(string)
                end = start + len(string)
                # 获取字符串在string_val中的左右字符
                left = string_val[start-1] if start-1 >= 0 else ""
                right = string_val[end] if end < len(string_val) else ""
                # 判断字符串是否合法
                if (self.law_left(left, string_val[start]) and self.law_right(right, string_val[end-1])):
                    result.add(string)
        return result

def main():
    # C:\Users\anankeliu\Desktop\uassetParse\temp\smali
    sS = smaliScan(sys.argv)
    sS.do_scan()    

if __name__ == "__main__":
    main()