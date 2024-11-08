import os
import sys
import time
import json
from macholib.MachO import MachO

import tool.parseHelper as PH

# 获取通用函数
check_file_exists = PH.check_file_exists
print_progress_bar = PH.print_progress_bar
setToString = PH.setToString
get_print_str_num = PH.get_print_str_num
scan_string_en = PH.scan_string_dict
scan_string_zh = PH.scan_string_zh
get_path = PH.get_path

class MachOParse(PH.BaseParse):
    def __init__(self, argv):
        super().__init__(argv)

        # 定义定制化参数
        self.data_file_end = ".json"
        self.parse_cmd_pre = r"radare2\rabin2 -z -N 2 -j "
        self.file_kind = "macho"

        self.ignore_file_paht = "PlugIns"   # 定义忽视文件路径
        # 填充扫描文件列表
        for root, dirs, files in os.walk(self.scan_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file in self.ignore_file_list or (self.ignore_file_paht != "" and self.ignore_file_paht in file_path):
                    continue 
                if self.no_parse and file.endswith(".json"):
                    self.scan_file_list.add(file_path)
                if not self.no_parse and self.check_macho_file(file_path):
                    self.scan_file_list.add(file_path)
        # 获取文件数量
        self.file_count = len(self.scan_file_list)

    def print_help(self):
        print("------------------------------------------------------------------------------------------------------")
        print("Welcome to use machOParse.py, a tool to parse and scan mach-o files.Please choose the following usages:")
        print("Usage: machOParse.py macho_folder_path [-choice]")
        self.print_help_choice()
        print("Usage: machOParse.py -sj json_path [-choice]")
        print("......")
        print("------------------------------------------------------------------------------------------------------")
        exit(0)

    def check_macho_file(self, file_path):
        with open(file_path, "rb") as f:
            magic = f.read(4)
            return magic in [b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']    # 根据魔数检测文件是否是mach-o文件

    # 扫描工具解析之外的节区，返回一个字典，字典的key为节区名，value为字典1，字典1的key为偏移地址，value为字符串
    def parse_exp_sections(self, macho_path, scan_report):
        macho = MachO(macho_path)
        # 定义需要扫描的段
        LC_SEGMENT = 0x1
        LC_SEGMENT_64 = 0x19
        # 需要utf-16le解码的节区
        sections_u = ['__ustring']
        # 需要ascii解码的节区
        sections_a = ['__swift5_typeref', '__swift5_capture', '__swift5_reflstr', '__swift5_fieldmd', '__swift5_types', '__swift5_assocty', '__swift5_proto', '__swift5_protos', 
        '__swift5_builtin', '__swift5_mpenum', '__unwind_info', '__eh_frame', '__const', '__objc_data', '__data']

        for header in macho.headers:
            for load_command, segment, sections in header.commands:
                if load_command.cmd == LC_SEGMENT or load_command.cmd == LC_SEGMENT_64:
                    segname = segment.segname.decode('utf-8').strip('\x00')
                    for section in sections:
                        sectname = section.sectname.decode('utf-8').strip('\x00')
                        # 工具已经帮我们做了
                        if sectname == '__const' and segname == '__TEXT':
                            continue

                    
                        wei = "weight:2"
                        if sectname in sections_a:
                            with open(macho_path, 'rb') as f:
                                f.seek(section.offset)
                                section_data = f.read(section.size)
                                # ascii解码
                                res_dict = self.decode_ascii_data(section_data, section.size, section.offset)
                                if res_dict:    #字典res_dict的key为偏移地址，value为字符串
                                    # 写入扫描结果
                                    for str_off, str_val in res_dict.items():
                                        scan_report[wei][str_val] = dict()
                                        scan_report[wei][str_val]["section"] = sectname 
                                        scan_report[wei][str_val]["file_offset"] = str_off
                                        scan_report[wei][str_val]["sen_str"] = 'true' 
                                        scan_report[wei][str_val]["have_zh"] = 'false'
                                
                        if sectname in sections_u:
                            with open(macho_path, 'rb') as f:
                                f.seek(section.offset)
                                section_data = f.read(section.size)
                                # UTF-16LE解码，获取字符串列表
                                res_dict = self.decode_utf16le_data(section_data, section.size, section.offset)
                                if res_dict:
                                    # 写入扫描结果
                                    for str_off, str_val in res_dict.items():
                                        scan_report[wei][str_val] = dict()
                                        scan_report[wei][str_val]["section"] = sectname 
                                        scan_report[wei][str_val]["file_offset"] = str_off
                                        scan_report[wei][str_val]["sen_str"] = 'true' 
                                        scan_report[wei][str_val]["have_zh"] = 'true'

        return
    # 重写扫描json文件函数
    def scan_data_file(self, json_file_path):
        # 获取报告模板
        scan_report = self.get_json_scan_dict(json_file_path)

        # 读取json文件并进行扫描
        with open(json_file_path, "r", encoding="utf-8") as f:
            json_dict = json.load(f)
            if "strings" not in json_dict.keys():
                print("This file is not a valid data file which form file parsed: " + json_file_path)
                return
            for string in json_dict["strings"]:
                str_size = string["size"]
                str_len = string["length"]
                str_off = string["paddr"]
                str_type = string["type"]
                str_val = string["string"]
                str_sec = string["section"]
                # 针对mach-o文件，根据所在节区给与不同权重
                if "__cstring" not in string["section"] and "__cfstring" not in string["section"]:
                    weight = 1
                else:
                    weight = 2

                # 进行字符串字典扫描
                result_str = scan_string_en(str_val, self.string_dict)
                # 进行中文扫描(如果可能存在中文的话)
                have_zh = 0
                if str_type == "utf8":
                    # 进行中文扫描
                    have_zh = scan_string_zh(str_val)

                if weight == 2:
                    wei = "weight:2"
                elif weight == 1:
                    wei = "weight:1"
                else:
                    wei = "weight:0"
                if have_zh > 0 or len(result_str) > 0:
                    scan_report[wei][str_val] = dict()
                    scan_report[wei][str_val]["section"] = str_sec 
                    scan_report[wei][str_val]["file_offset"] = str_off
                    scan_report[wei][str_val]["str_len"] = str_len
                    scan_report[wei][str_val]["str_size"] = str_size
                    scan_report[wei][str_val]["sen_str"] = setToString(result_str)
                    scan_report[wei][str_val]["have_zh"] = have_zh > 0

        # 扫描额外的段
        # 获取mach-o文件路径
        mach_path = self.scan_folder_path + scan_report['file_name'].replace('/', '\\')

        # 扫描额外的段
        self.parse_exp_sections(mach_path, scan_report)

        # 写入扫描结果
        self.write_json_file(scan_report)
        return

def main():
    mp = MachOParse(sys.argv)
    mp.do_scan()    

if __name__ == "__main__":
    main()