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


import logging
import datetime
import xml.etree.ElementTree as ET
def _scan_primary_xml():
    """
    扫描并解析primary.xml压缩文件，提取软件包信息、许可证和漏洞数据
    """


def _scan_repomd(repomd_path, base_repo_url):
    """
    扫描并解析repomd.xml文件，提取primary数据的URL和时间戳

    Args:
        repomd_path (str): repomd.xml文件的本地路径
        base_repo_url (str): 基础仓库URL地址

    Returns:
        tuple: 包含两个元素的元组：
               - primary_url (str): primary.xml.gz文件的完整URL地址，如果解析失败则为None
               - formatted_date (str): 格式化后的时间戳日期(YYYY-MM-DD)，如果解析失败则为None
    """

    try:
        # 解析XML文件
        tree = ET.parse(repomd_path)
        root = tree.getroot()

        # 定义XML命名空间
        namespace = {'repo': 'http://linux.duke.edu/metadata/repo'}

        # 查找type为primary的data元素
        primary_data = root.find(".//repo:data[@type='primary']", namespace)
        if primary_data is None:
            logging.error("在repomd.xml中未找到primary数据")
            return None, None

        # 提取location元素的href属性
        location = primary_data.find("repo:location", namespace)
        if location is None:
            logging.error("在primary数据中未找到location信息")
            return None, None

        href = location.get("href")
        if not href:
            logging.error("location元素中没有href属性")
            return None, None

        # 提取timestamp
        timestamp_elem = primary_data.find("repo:timestamp", namespace)
        if timestamp_elem is None:
            logging.error("在primary数据中未找到timestamp信息")
            return None, None

        timestamp_str = timestamp_elem.text
        if not timestamp_str:
            logging.error("timestamp元素中没有内容")
            return None, None

        # 将时间戳转换为日期格式
        try:
            timestamp_int = int(timestamp_str)
            formatted_date = datetime.datetime.fromtimestamp(
                timestamp_int).strftime("%Y-%m-%d")
        except ValueError:
            logging.error(f"时间戳格式无效: {timestamp_str}")
            return None, None

        # 拼接完整的URL
        primary_url = f"{base_repo_url}/update/source/{href.lstrip('/')}"
        return primary_url, formatted_date  # 返回格式化后的日期

    except ET.ParseError as e:
        logging.error(f"解析repomd.xml失败: {e}")
        return None, None
    except Exception as e:
        logging.error(f"处理repomd.xml时发生未知错误: {e}")
        return None, None



def _extract_primary_xml(text):
    """
    从给定的URL字符串中中提取primary.xml及其后续内容

    Args:
        text (str): 输入的文本字符串，通常是从URL中提取的部分路径

    Returns:
        str: 如果输入文本包含"primary.xml"，则返回从"primary.xml"开始的子字符串；
             如果不包含，则返回原始输入文本
    """

    before, separator, after = text.partition("primary.xml")
    if separator:
        return "primary.xml" + after
    return text

def scan_repo():
    """
    扫描单个源代码仓库，生成安全引入评估报告。
    """

