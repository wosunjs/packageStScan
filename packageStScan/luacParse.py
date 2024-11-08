import os
import sys
import time
import re

import tool.parseHelper as PH

# 获取通用函数
check_file_exists = PH.check_file_exists
print_progress_bar = PH.print_progress_bar
setToString = PH.setToString
get_print_str_num = PH.get_print_str_num
scan_string_en = PH.scan_string_dict
scan_string_zh = PH.scan_string_zh
get_path = PH.get_path
# -np C:\Users\anankeliu\Desktop\uassetParse\temp\luac

class luacParse(PH.BaseParse):
    def __init__(self, argv):
        super().__init__(argv)

        # 定义定制化参数
        self.data_file_end = ".lua.decode"
        self.parse_cmd_pre = r"luac -l -l "
        self.file_kind = "luac"

        # 填充扫描文件列表
        for root, dirs, files in os.walk(self.scan_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file in self.ignore_file_list or (self.ignore_file_paht != "" and self.ignore_file_paht in file_path):
                    continue
                if self.no_parse and file.endswith(".lua.decode"):
                    self.scan_file_list.add(file_path)
                if not self.no_parse and self.check_luac_file(file_path):
                    self.scan_file_list.add(file_path)
        # 获取文件数量
        self.file_count = len(self.scan_file_list)

    def print_help(self):
        print("------------------------------------------------------------------------------------------------------")
        print("Welcome to use luacParse.py, a tool to parse and scan luac files.Please choose the following usages:")
        print("Usage: luacParse.py luac_folder_path [-choice]")
        self.print_help_choice()
        print("Usage: luacParse.py -np .lua.decode_path [-choice]")
        print("......")
        print("------------------------------------------------------------------------------------------------------")
        exit(0)

    def check_luac_file(self, file_path):
        with open(file_path, "rb") as f:
            magic = f.read(4)
            # 检查文件是否为luac文件
            return magic in [b'\x1b\x4c\x75\x61']  # luac文件魔数为1B 4C 75 61
        
    # 重写解析文件方法为luac
    def scan_data_file(self, lua_decode_file_path):
        # 检查文件是否为空
        if os.path.getsize(lua_decode_file_path) == 0:
            return
        
        # 获取报告模板
        scan_report = self.get_json_scan_dict(lua_decode_file_path)

        # 读取luac可读字节码文件并进行扫描
        with open(lua_decode_file_path, "r", encoding="utf-8") as f:
            # 逐行读取文件
            line = f.readline()
            while line:
                num = 0
                if "constants (" in line and "for" in line:
                    type = "constants"
                    num = int(line.split("(")[1].split(")")[0]) # 获取常量表中常量数量，位于()之间

                elif "locals (" in line and "for" in line:
                    type = "locals"
                    num = int(line.split("(")[1].split(")")[0]) # 获取局部变量表中变量数量，位于()之间

                elif "upvalues (" in line and "for" in line:
                    type = "upvalues"
                    num = int(line.split("(")[1].split(")")[0]) # 获取upvalue表中upvalue数量，位于()之间
                else:
                    line = f.readline()
                    continue

                # 获取对应函数地址
                func_off = line.split(" ")[3].split(":")[0]    # 将函数地址转换作为key标记一组
                # 向下读取num行
                for i in range(num):
                    line = f.readline()
                    # 以制表符分隔当前行
                    line = line.split("\t")
                    string = line[2].split('\n')[0]
                    id = line[1]
                    # 进行字符串字典扫描
                    result_str = scan_string_en(string, self.string_dict)
                    have_zh = 0
                    decoded_string = ""
                    # 对字符串进行中文扫描(如果可能存在中文的话)
                    if '"' in string and '\\' in string:
                        # 去掉两侧的双引号
                        string = string[1:-1]
                        # 使用正则表达式匹配转义字符
                        pattern = re.compile(r'\\(\d{3})')
                        byte_values = pattern.findall(string)
                        # 以utf8编码格式进行解码, luac字节码中将中文以utf8编码进行了字符存储如\228\189\160
                        # 将匹配到的字符串转换为字节
                        bytes_string = bytes([int(byte_value) for byte_value in byte_values])
                        # 将字节解码为中文
                        decoded_string = bytes_string.decode('utf-8')
                        have_zh = scan_string_zh(decoded_string)
                    if have_zh > 0 or len(result_str) > 0:
                        wei = "weight:2"    # 暂不考虑字节码扫描误差
                        scan_report[wei][string] = dict()
                        if( decoded_string) : scan_report[wei][string]["str_val"] = decoded_string
                        scan_report[wei][string]["func_off"] = func_off 
                        scan_report[wei][string]["type"] = type
                        scan_report[wei][string]["str_id"] = id
                        scan_report[wei][string]["sen_str"] = setToString(result_str)
                        scan_report[wei][string]["have_zh"] = have_zh > 0
                # 向下读取
                line = f.readline()

        # 写入扫描结果
        self.write_json_file(scan_report)
        return

def main():
    # -np C:\Users\anankeliu\Desktop\uassetParse\temp\luac
    mp = luacParse(sys.argv)
    mp.do_scan()    

if __name__ == "__main__":
    main()