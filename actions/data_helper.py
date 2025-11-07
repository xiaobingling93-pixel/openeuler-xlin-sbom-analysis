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

import os
import json
import logging
import subprocess
import datetime
from pathlib import Path


def read_data_from_json(json_file_path):
    """
    从 JSON 文件中读取数据。

    Args:
        json_file_path (str): JSON 文件的路径。

    Returns:
        dict or list: 从 JSON 文件中读取的数据。可以是字典或列表。
    """

    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def save_data_to_json(data, json_file_path):
    """
    将数据保存到 JSON 文件中。

    Args:
        data (dict or list): 要保存的数据，可以是字典或列表。
        json_file_path (str): JSON 文件的路径。

    Returns:
        None
    """
    if data is not None:
        with open(json_file_path, 'w', encoding='utf-8') as json_file:
            json.dump(data, json_file, ensure_ascii=False, indent=4)

def save_docx_report(doc, docx_file_path):
    """
    将DOCX文档保存到文件

    Args:
        doc (Document): python-docx文档对象，要保存的文档
        docx_file_path (str): 输出文件路径，包括文件名和.docx扩展名

    Returns:
        None: 该函数不返回任何值，直接将文档保存到指定路径
    """

    # 确保输出目录存在
    output_dir = os.path.dirname(docx_file_path)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"创建目录: {output_dir}")

    # 保存文档
    doc.save(docx_file_path)


def convert_docx_to_pdf(docx_path, output_dir):
    """
    将DOCX文件转换为PDF并保存到指定目录

    Args:
        docx_path (str): 输入的DOCX文件路径
        output_dir (str): 输出PDF的目录路径

    Returns:
        str: 成功时返回生成的PDF路径，失败时返回None
    """

    # 检查输入文件是否存在
    if not os.path.isfile(docx_path):
        raise FileNotFoundError(f"输入文件不存在: {docx_path}")

    # 确保输出目录存在（如果不存在则创建）
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # 获取不带扩展名的文件名
    filename = Path(docx_path).stem

    try:
        # 使用LibreOffice进行转换
        command = [
            'libreoffice',
            '--headless',
            '--convert-to',
            'pdf',
            '--outdir',
            output_dir,
            docx_path
        ]

        # 执行转换命令
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )

        # 检查是否生成PDF文件
        pdf_path = os.path.join(output_dir, f"{filename}.pdf")
        if os.path.exists(pdf_path):
            return pdf_path
        else:
            raise RuntimeError("PDF文件生成失败")

    except subprocess.CalledProcessError as e:
        error_msg = f"转换失败: {e.stderr.decode('utf-8')}" if e.stderr else f"转换失败: {e}"
        raise RuntimeError(error_msg)
    except Exception as e:
        raise RuntimeError(f"发生未知错误: {str(e)}")


def setup_paths(output_base_dir, base_name_with_timestamp):
    """
    为给定的扫描目标统一创建并返回所有必需的路径。

    Args:
        output_base_dir (str): 用户指定的总输出目录。
        base_name_with_timestamp (str): 带有时间戳的唯一基础名称，例如 "pkg-1.0_20250915123000"。

    Returns:
        dict: 包含所有生成路径的字典。
    """

    output_dir = os.path.join(output_base_dir, base_name_with_timestamp)
    data_dir = os.path.join(output_dir, "分析记录")
    os.makedirs(data_dir, exist_ok=True)

    paths = {
        "output_dir": output_dir,
        "data_dir": data_dir,
        "docx_report": os.path.join(output_dir, f"{base_name_with_timestamp} 安全引入评估报告.docx"),
        "licenses_pie_chart": os.path.join(data_dir, f"{base_name_with_timestamp} 许可证分布图.png"),
        "dep_scan_results": os.path.join(data_dir, f"{base_name_with_timestamp} 依赖项扫描结果.json"),
        "files_info": os.path.join(data_dir, f"{base_name_with_timestamp} 文件级许可证信息.json"),
        "dep_licenses_pie_chart": os.path.join(data_dir, f"{base_name_with_timestamp} 依赖项许可证分布图.png"),
        "vulns_record": os.path.join(data_dir, f"{base_name_with_timestamp} 漏洞扫描结果.json"),
    }
    return paths


def get_scan_dates(config):
    """
    根据配置确定报告的开始和结束日期。

    Args:
        config (dict): 配置对象，包含日期设置相关信息。
                      如果config['general']['date_setting']['fixed_date']为True，
                      则使用config['general']['date_setting']['date']作为固定日期；
                      否则使用当前日期。

    Returns:
        tuple: 包含两个元素的元组，分别为开始日期和结束日期字符串，格式为"YYYY-MM-DD"。
               如果使用固定日期，则两个元素相同；否则都为当前日期。
    """

    if config.get('general', {}).get('date_setting', {}).get('fixed_date'):
        date = config.get('general', {}).get('date_setting', {}).get('date')
        return date, date
    else:
        today_str = datetime.date.today().strftime("%Y-%m-%d")
        return today_str, today_str


def log_scan_summary():
    """
    记录扫描结果摘要信息，包括成功处理的包数量和失败的包列表。
    """
    # TODO: 添加日志记录逻辑
