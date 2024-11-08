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

class uassetParse(PH.BaseParse):
    def __init__(self, argv):
        super().__init__(argv)

        # 定义定制化参数
        self.ue_version = "4.18"
        self.data_file_end = ".json"
        self.parse_cmd_pre = r"uassetParseBase\uassetParseBase.exe "
        self.scan_report_path = os.path.join(os.getcwd(), "res\\uasset_" + self.now_time + ".json")    # 报告保存文件夹临时为当前目录下的res文件夹

        # 填充扫描文件列表
        for root, dirs, files in os.walk(self.scan_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file in self.ignore_file_list or (self.ignore_file_paht != "" and self.ignore_file_paht in file_path):
                    continue 
                if self.no_parse and file.endswith(".json"):
                    self.scan_file_list.add(file_path)
                if not self.no_parse and self.check_uasset_file(file_path):
                    self.scan_file_list.add(file_path)
        # 获取文件数量
        self.file_count = len(self.scan_file_list)

    def print_help(self):
        print("-------------------------------------------------------------------------------------------------")
        print("Welcome to use uassetParse.py, a tool to parse .uasset files.Please choose the following usages:")
        print("Usage: uassetParse.py uasset_folder_path [-choice]")
        self.print_help_choice()
        print("-v: choose the Unreal version of this Parse.")
        print("......")
        print("------------------------------------------------------------------------------------------------")
        exit(0)

    def check_ue_version(self, tmp_ue_version):
        # 检查UE版本
        version_list = tmp_ue_version.split(".")
        big_version = int(version_list[0])
        small_version = int(version_list[1])
        # 判断UE版本是否在可解析版本范围内
        if big_version == 4:
            if small_version <= 27 & small_version >= 0:
                return True
        elif big_version == 5:
            if small_version <= 3 & small_version >= 0:
                return True
        else:
            return False

    def parse_argv(self, argv):
        super().parse_argv(argv)
        # 添加定制化参数选项(ue版本)
        if len(argv) > 2:
            for i in range(2, len(argv)):
                if argv[i] == "-v":
                    tmp_ue_version = sys.argv[i + 1]
                    if(self.check_ue_version(tmp_ue_version)):
                        self.ue_version = tmp_ue_version
                        return

    def check_uasset_file(self, file_path):
        with open(file_path, "rb") as f:
            magic = f.read(4)
            # 检查文件是否为uasset文件
            return magic in [b'\xc1\x83\x2a\x9e']  # uasset文件魔数为C1 83 2A 9E
        
    def get_cmd(self, file_path, data_file_path):
        return self.parse_cmd_pre + file_path + " " + data_file_path + " " + self.ue_version
        
    # 重写扫描json文件函数
    def scan_data_file(self, json_file_path):
        # 获取报告模板
        scan_report = self.get_json_scan_dict(json_file_path)
        # 删除scan_report中的weight字段(uasset的扫描结果具有特殊性)
        del scan_report["weight:0"]
        del scan_report["weight:1"]
        del scan_report["weight:2"]
        # 添加NameMap字段，uasset的报告模板初始包括file_path、NameMap
        scan_report["NameMap"] = dict()


        # 读取json文件并进行扫描
        with open(json_file_path, "r", encoding="utf-8") as f:
            json_dict = json.load(f)

            # 获取json文件中键NameMap对应的集合值，并进行扫描
            name_map = json_dict["NameMap"]
            for name in name_map:
                # 对name进行字典扫描
                result_str = scan_string_en(name, self.string_dict)
                # 对name进行中文扫描
                have_zh = scan_string_zh(name)
                # 将对name的扫描结果添加进name_scan_set
                if result_str != set() or have_zh:
                    # 如果扫描结果不为空，将name作为key，扫描结果作为value添加进name_scan_set
                    scan_report["NameMap"][name] = dict()
                    scan_report["NameMap"][name]["Value"] = name
                    scan_report["NameMap"][name]["sen_str"] = setToString(result_str)
                    scan_report["NameMap"][name]["have_zh"] = have_zh > 0

            # 获取json文件中键Exports对应的集合值，并进行扫描
            exports = json_dict["Exports"]
            for export in exports:
                # 如果type中存在"NormalExport"字符串，则可能为蓝图变量存放字符串默认值/也可能直接为UI蓝图的TextData
                if "NormalExport" in export["$type"]:
                    # 获取export中的键Data对应的值
                    Data = export["Data"]
                    # 将ObjectName作为key，将Data扫描结果作为value添加进scan_report
                    ObjectName = export["ObjectName"]
                    Data_res = dict()
                    for data in Data:
                        # 为单个data构造一个字典
                        data_name = data["Name"]
                        # 如果data中存在"TextPropertyData"字符串，则为变量的字符串值
                        str = ""
                        if "TextPropertyData" in data["$type"]:
                            str = data["CultureInvariantString"]
                        if "NamePropertyData" in data["$type"] or "StrPropertyData" in data["$type"]:
                            str = data["Value"]
                        result_str = scan_string_en(str, self.string_dict)
                        have_zh = scan_string_zh(str)
                        # 将对data的Name作为key，扫描结果添加进Data_res
                        if result_str != set() or have_zh:
                            Data_res[data_name] = dict()
                            Data_res[data_name]["Value"] = str
                            Data_res[data_name]["sen_str"] = setToString(result_str)
                            Data_res[data_name]["have_zh"] = have_zh > 0
                        
                    if Data_res != dict():
                        scan_report[ObjectName] = Data_res

                # 如果type中存在"FunctionExport"字符串，则可能为蓝图事件图表，其中可能存在字符串常量右值
                if "FunctionExport" in export["$type"]:
                    # 获取ObjectName作为key，对事件蓝图的扫描结果(集合)作为value添加进scan_report
                    ObjectName = export["ObjectName"]
                    Obj_res = dict()
                    i = 0
                    for sbc in export["ScriptBytecode"]:
                        if "EX_Let" in sbc["$type"] and "EX_Let_1" in sbc.keys():
                            exp = sbc["Expression"]
                            # 如果exp不为空
                            if exp :
                                val = ""
                                if "EX_TextConst" in exp["$type"]:
                                    # 存在TextConst字符串，进行字符串扫描和中文扫描
                                    if not exp["Value"] or not exp["Value"]["LocalizedSource"] or not exp["Value"]["LocalizedSource"]["Value"]:
                                        continue
                                    val = exp["Value"]["LocalizedSource"]["Value"]
                                    expName = "事件蓝图FText常量"
                                elif "EX_UnicodeStringConst" in exp["$type"]:
                                    # 存在UnicodeStringConst字符串，进行字符串扫描和中文扫描
                                    val = exp["Value"]
                                    expName = "事件蓝图FString常量"
                                elif "EX_NameConst" in exp["$type"]:
                                    # 存在NameConst字符串，进行字符串扫描和中文扫描
                                    val = exp["Value"]
                                    expName = "事件蓝图FName常量"

                                if val == "":     
                                    continue
                                result_str = scan_string_en(val, self.string_dict)
                                have_zh = scan_string_zh(val)
                                # 将对expName作为key，exp扫描结果作为value添加进Obj_res
                                exp_dict = dict()
                                if result_str != set() or have_zh:
                                    exp_dict[expName] = dict()
                                    exp_dict[expName]["Value"] = val
                                    exp_dict[expName]["sen_str"] = setToString(result_str)
                                    exp_dict[expName]["have_zh"] = have_zh > 0

                                if exp_dict != dict():
                                    Obj_res[i] = exp_dict
                                    i += 1
                    if Obj_res != dict():
                        scan_report[ObjectName] = Obj_res

        if scan_report != dict():
            # 检测scan_report中是否有检测结果
            if len(scan_report.keys()) < 3 and scan_report["NameMap"] == dict():
                return

            # 将数据追加写入JSON文件，并设置indent参数为4
            with open(self.scan_report_path, "a", encoding="utf-8") as f:
                json.dump(scan_report, f, ensure_ascii=False, indent=4)
                f.write("\n")

        return                

        

def main():
    uassetParse(sys.argv).do_scan()

if __name__ == "__main__":
    main()