import sys
import json

def print_help():
    print("Welcome to use json file array tool, a tool to make json file more friendly to view.")
    print("Usage1: json_array_tool.py json_input_file json_ouput_file")
    print("Usage2: json_array_tool.py json_file")
    exit(0)

def main():
    if len(sys.argv) < 2 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
        print_help()

    # 通过用户输入获取json文件路径
    json_input_path = sys.argv[1]
    if len(sys.argv) > 2:
        json_output_path = sys.argv[2]
    else:
        json_output_path = json_input_path
    
    # 读取输入文件中的JSON数据
    with open(json_input_path, "r", encoding="utf-8") as file:
        data = json.load(file)
    
    # 将JSON数据排版（缩进为4个空格）
    formatted_data = json.dumps(data, ensure_ascii=False, indent=4, sort_keys=True)
    
    # 将排版后的JSON数据写入输出文件
    with open(json_output_path, "w", encoding="utf-8") as file:
        file.write(formatted_data)

if __name__ == "__main__":
    main()