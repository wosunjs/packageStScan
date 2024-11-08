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

class elfParse(PH.BaseParse):
    def __init__(self, argv):
        super().__init__(argv)

        # 定义定制化参数
        self.data_file_end = ".json"
        self.parse_cmd_pre = r"radare2\rabin2 -z -N 2 -a arm -j "
        self.scan_report_path = os.path.join(os.getcwd(), "res\\elf_" + self.now_time + ".json")    # 报告保存文件夹临时为当前目录下的res文件夹

        # 忽视文件列表
        self.ignore_file_list = {"libUE4.so"}
        # 填充扫描文件列表
        for root, dirs, files in os.walk(self.scan_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file in self.ignore_file_list or (self.ignore_file_paht != "" and self.ignore_file_paht in file_path):
                    continue 
                if self.no_parse and file.endswith(".json"):
                    self.scan_file_list.add(file_path)
                if not self.no_parse and self.check_elf_file(file_path):
                    self.scan_file_list.add(file_path)
        # 获取文件数量
        self.file_count = len(self.scan_file_list)

    def print_help(self):
        print("------------------------------------------------------------------------------------------------------")
        print("Welcome to use elfParse.py, a tool to parse and scan elf files.Please choose the following usages:")
        print("Usage: elfParse.py macho_folder_path [-choice]")
        self.print_help_choice()
        print("Usage: elfParse.py -sj json_path [-choice]")
        print("......")
        print("------------------------------------------------------------------------------------------------------")
        exit(0)

    def check_elf_file(self, file_path):
        return file_path.endswith(".so")    # 目前elf文件仅针对.so文件进行扫描
    
    # 重写扫描json文件函数
    def scan_data_file(self, json_file_path):
        # 获取报告模板
        scan_report = self.get_json_scan_dict(json_file_path)

        # 读取json文件并进行扫描
        with open(json_file_path, "r", encoding="utf-8") as f:
            json_dict = json.load(f)
            if "strings" not in json_dict.keys():
                print("This file is not a valid data file which form file parsed : " + json_file_path)
                return
            for str in json_dict["strings"]:
                str_size = str["size"]
                str_len = str["length"]
                str_off = str["paddr"]
                str_type = str["type"]
                str_val = str["string"]
                # elf中的字符串中文为utf-8
                # 进行字符串字典扫描
                result_str = scan_string_en(str_val, self.string_dict)
                # 进行中文扫描(如果可能存在中文的话)
                have_zh = scan_string_zh(str_val)

                # 进行权重计算
                weight = 0
                if have_zh > 1 or len(result_str) > 0:
                    # 有多个中文或字符串字典扫描结果不为空
                    weight = 2
                if weight == 0:
                    # 如果中文只有1个且字符串字典扫描结果为空，检测字符合规性
                    str_num = get_print_str_num(str_val)     # 获取字符串中可打印字母数量
                    # 如果str_num和中文数量少于字符串长度的一半则认为可能误判
                    if str_num + have_zh > len(str_val) / 2:
                        weight = 1
                if weight == 2:
                    wei = "weight:2"
                elif weight == 1:
                    wei = "weight:1"
                else:
                    wei = "weight:0"
                if have_zh > 0 or len(result_str) > 0:
                    scan_report[wei][str_val] = dict()
                    scan_report[wei][str_val]["file_offset"] = str_off
                    scan_report[wei][str_val]["str_len"] = str_len
                    scan_report[wei][str_val]["str_size"] = str_size
                    scan_report[wei][str_val]["sen_str"] = setToString(result_str)
                    scan_report[wei][str_val]["have_zh"] = have_zh > 0

        # 写入扫描结果
        self.write_json_file(scan_report)
        return

def main():
    elfParse(sys.argv).do_scan()

if __name__ == "__main__":
    main()