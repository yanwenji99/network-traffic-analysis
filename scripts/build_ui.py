import os
import PyInstaller.__main__

# 项目根目录
base_dir = os.path.dirname(os.path.abspath(__file__))

# 打包命令
PyInstaller.__main__.run([
    '--name=NetworkAnalyzer',  # 生成的EXE文件名
    '--onefile',  # 生成单个EXE文件
    '--windowed',  # 无控制台窗口
    '--add-data=python;python',  # 包含python目录
    '--add-data=data;data',  # 包含data目录
    '--add-data=build/bin;build/bin',  # 包含C++核心程序
    '--add-data=scripts;scripts',  # 包含脚本目录
    '--paths=.',  # 搜索路径
    'python/ui_gui.py'  # 要打包的主脚本
])