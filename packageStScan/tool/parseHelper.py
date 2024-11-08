# 提供解析所使用的通用函数
import os
import sys
import time
import threading
import queue
import json

# 解析基类
class BaseParse:
    def __init__(self, argv):
        # 声明解析所需变量
        self.now_time = str(int(time.time()))   # 保存当前时间，用于文件名
        self.file_count = 0  # 保存当前扫描文件总数
        self.string_dict = set() # 字符串扫描字典
        self.is_scan_zh = True   # 中文扫描开关
        self.no_parse = False   # 不解析文件开关(当只需要扫描解析后的产物时，打开该参数)
        self.ignore_file_list = set()   # 忽视文件集合
        self.ignore_file_paht = ""   # 忽视文件路径
        self.scan_file_list = set()    # 需扫描文件集合

        self.data_file_end = ""   # 数据文件后缀
        self.parse_cmd_pre = ""   # 解析命令前缀
        self.file_kind = ""   # 文件类型

        self.thread_count = 40   # 解析线程数
        self.queue_lock = threading.Lock()   # 解析线程锁
        self.exit_flag = False   # 解析线程退出标志
        self.work_queue = queue.Queue()   # 解析线程队列
        self.threads = []    # 解析线程列表
    
        # 初始化路径参数
        self.scan_folder_path = ""  # 待扫描文件夹路径
        self.scan_report_path = ""  # 报告保存文件夹临时为当前目录下的res文件夹
        self.data_floder_path = ""  # 临时数据文件夹临时为当前目录下的temp\data\time_so文件夹
        self.string_dict_path = r"C:\Users\anankeliu\Desktop\uassetParse\temp\str_dict.txt"  # 字典路径(通过输入字典路径来开启字典字符串扫描)

        self.parse_argv(argv)

    def print_help(self):
        print("------------------------------------------------------------------------------------------------------")
        print("Welcome to use Parse.py, a tool to parse and scan files.Please choose the following usages:")
        print("Usage: Parse.py scan_folder_path [-choice]")
        self.print_help_choice()
        print("Usage: luacParse.py -np .lua.decode_path [-choice]")
        print("......")
        print("------------------------------------------------------------------------------------------------------")
        exit(0)

    def print_help_choice(self):
        print("-r [scan_path]: set the scan report file save path.")
        print("-a [data_path]: set the tmp parse data file save path.")
        print("-d [dict_path]: set the dict which is used for string scan.")
        print("-t [thread_num]: set the num of parsing threads.")
        print("-zh: open the switch to scan hidden Chinese.")
        print("-h: this help message")
        print("-np [.lua.decode_path]: just scan the res folder which already parsed.")

    def parse_argv(self, argv):
        # 检测是否打印帮助信息
        #if len(argv) < 2 or argv[1] == "-h" or argv[1] == "--help":
        if len(argv) < 2 or "-h" in argv or "--help" in argv:
            self.print_help()

        # 解析第一(第二)参数,获取扫描路径
        if argv[1] == "-np":
            if len(argv) < 3:
                self.print_help()
            else:
                self.no_parse = True
                self.scan_folder_path = get_path(argv[2])
                self.data_floder_path = get_path(argv[2])
        else:
            self.scan_folder_path = get_path(argv[1])

        # 解析后续选项
        if len(argv) > 2:
            for i in range(2, len(argv)):
                if argv[i] == "-r":
                    i += 1
                    self.scan_report_path = get_path(argv[i])
                if argv[i] == "-a":
                    i += 1
                    self.data_floder_path = get_path(argv[i])
                if argv[i] == "-d":
                    i += 1
                    self.string_dict_path = get_path(argv[i])
                if argv[i] == "-t":
                    tmp_thread_num = int(argv[i + 1])
                    if tmp_thread_num > 0 :
                        self.thread_count = tmp_thread_num
                        i += 1
                # 如果是-zh参数，则将is_scan_zh改为True，但目前默认扫描全开
                if argv[i] == "-zh":
                    self.is_scan_zh = True

    def path_init(self):
        # 检查所需各项文件夹是否存在，不存在则使用默认赋值
        if self.scan_report_path == "":
            self.scan_report_path = os.path.join(os.getcwd(), "res\\" + self.file_kind + "_" + self.now_time + ".json")
        if self.data_floder_path == "":
            self.data_floder_path = os.path.join(os.getcwd(), "temp\\data\\" + self.now_time + "_" + self.file_kind)
        if self.string_dict_path != "":    
            self.string_dict_path = os.path.join(os.getcwd(), "temp\\" + "str_dict.txt") 

        # 检查扫描文件列表

    def print_end(self):
        print("Scan file num:", self.file_count)
        print("--------------------------------------------------------------------------------------------------------------------------")

    def do_scan(self):
        # 初始化各路径
        self.path_init()
        check_file_exists(self.data_floder_path)

        # 开始扫描
        print("--------------------------------------------------------------------------------------------------------------------------")
        print("Scan Info......")
        print("Scan folder path:", self.scan_folder_path)
        print("Scan report path:", self.scan_report_path)
        print("Temp floder path:", self.data_floder_path)
        print("String dict path:", self.string_dict_path)
        print("Parse thread num:", self.thread_count)
        print("Is scan Chinese:", self.is_scan_zh)
        print("...............")

        # 遍历待扫描文件列表,完成解析工作
        if not self.no_parse:
            # 创建解析线程
            print("Create thread......")
            # 创建解析线程
            for i in range(self.thread_count):
                thread = parse_thread(i + 1, "Thread-" + str(i + 1), self.work_queue, self)
                thread.start()
                self.threads.append(thread)
            print("Creation completed!")

            # 开始解析
            print("Start parse file......")
            start_time = time.time()     # 统计时间
            self.parse_file_folder()
            end_time = time.time()
            print("\nParse done! Use time:", end_time - start_time, "s")

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

        # 遍历data文件夹，对其进行扫描
        print("Start Scanning data file.....")
        start_time = time.time()
        # 对scan_report_path文件进行清空(新建)
        open(self.scan_report_path, "w", encoding="utf-8")
        # 开始扫描并写入报告
        self.scan_data_folder()
        end_time = time.time()
        print("\nScan done! Use time:", end_time - start_time, "s")
        self.print_end()

    def get_cmd(self, file_path, data_file_path):
        return self.parse_cmd_pre + file_path + " > " + data_file_path

    # 使用接口和组件模式完成文件夹解析和扫描
    def parse_file_folder(self):
        # 填充任务队列
        self.queue_lock.acquire()
        for file_path in self.scan_file_list:
            # 获取对应data文件路径(源文件夹下相对路径上同名文件)
            pre_path = file_path.replace(self.scan_folder_path, "") # 获取文件相对路径
            pre_path = os.path.dirname(pre_path)   # 去掉文件名
            now_data_floder_path = self.data_floder_path + pre_path  # 组合得到data文件夹路径
            # 判断now_data_floder_path路径是否存在，不存在则创建
            check_file_exists(now_data_floder_path)
            # 组合对应data件路径
            data_file_path = os.path.join(now_data_floder_path, os.path.basename(file_path) + self.data_file_end)
            # 组合执行解析文件指令
            cmd = self.get_cmd(file_path, data_file_path)
            self.work_queue.put(cmd)
        self.queue_lock.release()

        # 开始解析，等待线程队列清空
        while not self.work_queue.empty():
            # 获取任务队列剩余任务数量以更新任务进度
            remain_count = self.work_queue.qsize()
            file_finish_count = self.file_count - remain_count
            # 打印进度条
            sys.stdout.write("\r                                                                                                                       ")
            print_progress_bar(file_finish_count, self.file_count, "Parsing file")
            pass
        # 通知线程退出
        self.exit_flag = True
        # 等待所有线程退出
        for t in self.threads:
            # 判断线程是否完成
            t.join()
        # 打印完成进度条
        sys.stdout.write("\r                                                                                                                       ")
        str_out = "\rProgress:" + " |"+ '█' * 50 + "|" + "100.00%"
        sys.stdout.write(str_out)
        return
    
    def scan_data_folder(self):
        # 遍历data_floder_path路径下所有待扫描文件文件
        file_scan_count = 0
        for root, dirs, files in os.walk(self.data_floder_path):
            for file in files:
                if file.endswith(self.data_file_end):
                    # 获取data文件路径
                    data_file_path = os.path.join(root, file)
                    # 扫描data文件
                    self.scan_data_file(data_file_path)
                    # 打印进度
                    file_scan_count += 1
                    print_progress_bar(file_scan_count, self.file_count, "Scanning")

    # 以下为定义好的扫描单个文件处理接口函数
    def scan_data_file(self, data_file_path):
        return
    
    # 供子线程调用读取任务队列完成解析工作
    def parse_file(self, q):
        while not self.exit_flag:
            self.queue_lock.acquire()
            if not self.work_queue.empty():
                data = q.get()
                self.queue_lock.release()
                sys.stdout.flush()
                os.system(data)
            else:
                self.queue_lock.release()
            # 使线程休眠一段时间，降低单个线程占用CPU时间'
            time.sleep(0.1)

    # 获取一个json文件扫描字典
    def get_json_scan_dict(self, json_file_path):
        # 检测文件是否为空
        if os.path.getsize(json_file_path) == 0:
            return

        # 记录扫描结果为字典(key为文件相对路径)
        scan_report = dict()
        # 将相对路径添加进扫描结果
        source_file_path = os.path.abspath(json_file_path)             # 获取绝对路径
        source_file_path = source_file_path.replace(self.data_floder_path, "") # 消去data_floder_path
        source_file_path = source_file_path.replace(".json", "")       # 去掉后缀
        source_file_path = source_file_path.replace("\\", "/")         # 将路径中的\\替换为/
        scan_report["file_name"] = source_file_path
        # 将各权重添加进扫描结果
        scan_report["weight:2"] = dict()
        scan_report["weight:2"]["string_num"] = 0
        scan_report["weight:1"] = dict()
        scan_report["weight:1"]["string_num"] = 0
        scan_report["weight:0"] = dict()
        scan_report["weight:0"]["string_num"] = 0
        return scan_report
    
    # 将扫描结果写入json文件
    def write_json_file(self, scan_report):
        # 扫描为空则跳过写入该文件结果
        if len(scan_report["weight:2"]) < 2 and len(scan_report["weight:1"]) < 2 and len(scan_report["weight:0"]) < 2:
            return
        scan_report["weight:2"]["string_num"] = len(scan_report["weight:2"]) - 1
        scan_report["weight:1"]["string_num"] = len(scan_report["weight:1"]) - 1
        scan_report["weight:0"]["string_num"] = len(scan_report["weight:0"]) - 1
        # 将数据追加写入JSON文件，并设置indent参数为4
        with open(self.scan_report_path, "a", encoding="utf-8") as f:
            json.dump(scan_report, f, ensure_ascii=False, indent=4)
            f.write("\n")
    
    # 以utf-16le 解码数据段,传入数据段、数据段大小、数据段偏移量
    def decode_utf16le_data(self, byte_data, section_size, section_offset):
        ret = {}
        string = ''
        bit_pos = 0

        while bit_pos < section_size:
            # 获取两位比特
            bit0 = byte_data[bit_pos].to_bytes(1, 'little')
            bit1 = byte_data[bit_pos + 1].to_bytes(1, 'little')
            # 将两位比特组合
            bit_pos += 2
            bits = (bit0 + bit1)

            # 检查是否为 0x00
            if bits.hex() == '0000':
                if string != '' and (scan_string_zh(string) > 0 or len(scan_string_dict(string, self.string_dict)) > 0):
                    ret[bit_pos + section_offset] = string
                string = ''
                continue
            # 将两位比特转换为字节，并进行 UTF-16LE 解码
            try:
                decoded_char = bits.decode('utf-16le')
                string += decoded_char
            except UnicodeDecodeError:
                #print(f"Failed to decode bytes: {bits}")
                continue

        return ret

    # 以ascii解码数据段,传入数据段、数据段大小、数据段偏移量
    def decode_ascii_data(self, byte_data, section_size, section_offset):
        ret = {}
        string = ''
        bit_pos = 0

        while bit_pos < section_size:
            # 获取一位比特
            bit = byte_data[bit_pos].to_bytes(1, 'little')
            bit_pos += 1
            # 检查是否为 0x00
            if bit.hex() == '00':
                if string != '' and len(scan_string_dict(string, self.string_dict)) > 0:    # 只有长度大于1的字符串我们才认为合法
                    ret[bit_pos + section_offset] = string
                string = ''
                continue
            # 进行解码
            try:
                decoded_char = bit.decode('ascii')
                string += decoded_char
            # 遇到非打印字符按\x00处理
            except UnicodeDecodeError:
                if string != '' and len(scan_string_dict(string, self.string_dict)) > 0:
                    ret[bit_pos + section_offset] = string
                string = ''
                continue

        return ret

    def useful_str_len(self, string):
        num = 0
        for i in range(len(string)):
            if string[i] == ' ':
                continue
            num += 1
        return num

# 解析线程类
class parse_thread(threading.Thread):
    def __init__(self, threadID, name, q, parse_obj):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.q = q
        self.parse_obj = parse_obj
    def run(self):
        BaseParse.parse_file(self.parse_obj, self.q)

# 根据魔数检测文件是否是mach-o文件
def check_macho_file(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)
        return magic in [b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']

# 检查文件是否存在，不存在则创建
def check_file_exists(file_path):
    if not os.path.exists(file_path):
        try:
            os.makedirs(file_path)
        except:
            print("Create path failed, please check the path : {file_path}")
            exit(0)

# 路径传递，检查路径a_path是否存在，如果存在则传给b_path，否则报错退出
def get_path(a_path):
    if not os.path.exists(a_path):
        print("The path is not exists, please check the path : ", a_path)
        exit(0)
    return a_path

# 打印进度条
def print_progress_bar(progress, total, head):
    percent = (progress / total) * 100
    filled_length = int(50 * progress // total)
    bar = '█' * filled_length + '-' * (50 - filled_length)
    sys.stdout.write('\r%s: |%s| %.2f%%' % (head, bar, percent))
    sys.stdout.flush()

# 将set转换为字符串
def setToString(set_value):
    if type(set_value) != set:
        return ""
    str = ""
    for i in set_value:
        str += i + "、"
    str = str[:-1]
    return str

# 获取字符串中英文字母的数量
def get_print_str_num(str):
    str_num = 0
    for i in str:
        if (i > 'a' and i < 'z') or (i > 'A' and i < 'Z'):
            str_num += 1
    return str_num

# 检查字符左侧是否是合法分隔
def law_left(left, first):
    # 如果左侧为空格、数字、"_"、"."、""、"'"、"""则合法
    if left == " " or left == "." or left == "_" or left == "" or left == "\'" or left == "\"" or left.isnumeric():
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
def law_right(right, last):
    # 如果右侧为空格、数字、"_"、"."、""则合法
    if right == " " or right == "." or right == "_" or right == "" or right == "\'" or right == "\"" or right.isnumeric():
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
def scan_string_dict(string_val, string_dict):
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
            if (law_left(left, string_val[start]) and law_right(right, string_val[end-1])):
                result.add(string)
    return result

# 扫描字符串中的中文，返回其中中文的数量
def scan_string_zh(string_val):
    # 将string_val转换成字符串,防止NoneType
    if type(string_val) != str:
        string_val = str(string_val)
    num = 0
    # 遍历字符串中的字符
    for char in string_val:
        # 判断字符是否为中文
    #     if ("\u4e00" <= char <= "\u9fff") or \
    #    ("\u3105" <= char <= "\u312f") or \
    #    ("\u3400" <= char <= "\u4dbf") or \
    #    ("\uF900" <= char <= "\uFAFF") or \
    #    ("\u20000" <= char <= "\u2EBE0"):
        #if ("\u4e00" <= char <= "\u9fff"):      # \u9fa5
        if ("\u4e00" <= char <= "\u9fa5") :
            num += 1
    return num
    

if __name__ == "__main__":
    file_path = r"C:\Users\anankeliu\Desktop\PUBGM_iOS_Release3.3\Payload\ShadowTrackerExtra.app"
    # 遍历文件夹下文件
    for root, dirs, files in os.walk(file_path):
        for file in files:
            # 获取文件绝对地址
            file_path = os.path.join(root, file)
            # if check_macho_file(file_path):
                ## 输出文件路径
                #print(file_path)
