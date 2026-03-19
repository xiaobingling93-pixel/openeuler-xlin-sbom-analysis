# Copyright (c) 2025 Linx Software, Inc.
#
# xlin-sbom-analysis tool is licensed under Mulan PSL v2.

# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
# http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.


from actions import OSV_SCANNER
import subprocess
import os

def dep_scan(target_dir, output_file):
    """
    使用osv-scanner对指定目录进行依赖扫描，并将结果保存为JSON文件

    Args:
        target_dir (str): 要扫描的目录路径
        output_file (str): 输出JSON文件的完整路径

    Returns:
        None: 该函数不返回任何值，扫描结果直接保存到指定的输出文件中
    """
    
    # 确保输出文件的目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir:  # 确保目录路径非空
        os.makedirs(output_dir, exist_ok=True)
    
    command = [
        OSV_SCANNER,
        "scan",
        "-r", target_dir,
        "--licenses",
        "--all-packages",
        "--format", "json",
        "--output", output_file  # 直接使用传入的文件路径
    ]
    
    subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False
    )
    