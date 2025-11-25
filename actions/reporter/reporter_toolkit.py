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

import re
from typing import List, Dict
from actions.package import Package
from actions.license_helper import (
    split_license,
    get_license_category,
    LICENSE_CATEGORY_DETAILS
)

def _find_non_commercial_licenses():
    """
    查找禁止商业用途的许可证
    """
    # TODO: 通过许可证数据集查找禁止商业用途的许可证


def categorize_packages(packages: List[Package]) -> Dict[str, List[Package]]:
    """
    将软件包按照许可证类别进行分类

    Args:
        packages (List[Package]): 软件包列表，每个软件包包含名称、版本和许可证信息

    Returns:
        Dict[str, List[Package]]: 按许可证类别分类的字典，键为许可证类别名称，
                                  值为属于该类别的软件包列表
    """

    license_categories = [item["scancode_category"]
                          for item in LICENSE_CATEGORY_DETAILS]
    categorized_dict = {category: [] for category in license_categories}

    for package in packages:
        for category in package.categories:
            if category in categorized_dict:
                categorized_dict[category].append(package)

    return categorized_dict


def analyze_licenses(license_summary):
    """
    分析许可证数据并返回结构化结果

    Args:
        license_summary (list): 许可证摘要信息列表，每个元素为包含许可证信息的字典，
                                通常包含许可证名称等字段

    Returns:
        dict: 包含许可证分析结果的字典，包含以下键值对：
            - "all_licenses" (list): 所有许可证列表，每个元素为(name, category)元组
            - "category_counts" (dict): 各分类的许可证计数，键为分类名称，值为该分类下的许可证数量
            - "category_licenses" (dict): 各分类的具体许可证集合，键为分类名称，值为该分类下的许可证名称集合
    """

    # 收集所有许可证及其类别
    all_licenses = []
    for lic in license_summary:
        license_names = split_license(lic["name"])
        for name in license_names:
            category = get_license_category(name)
            all_licenses.append((name, category))

    # 初始化分类统计
    categories = [item["scancode_category"]
                  for item in LICENSE_CATEGORY_DETAILS] + ["Unknown"]
    category_counts = {cat: set() for cat in categories}
    category_licenses = {cat: set() for cat in categories}

    # 统计各类别许可证
    for name, category in all_licenses:
        normalized_category = category if category in category_counts else "Unknown"
        category_counts[normalized_category].add(name)
        category_licenses[normalized_category].add(name)

    return {
        "all_licenses": all_licenses,
        "category_counts": {k: len(v) for k, v in category_counts.items()},
        "category_licenses": category_licenses
    }



def count_vulnerability_severity(packages):
    """
    统计包列表中所有漏洞的严重级别分布

    Args:
        packages: 由Package对象组成的列表

    Returns:
        dict: 包含严重级别统计的字典
    """

    severity_count = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    # 定义关键词映射（包括同义词处理）
    severity_keywords = {
        "critical": ["critical"],
        "high": ["high"],
        "medium": ["medium", "moderate"],
        "low": ["low"]
    }

    for package in packages:
        for vuln in package.vulnerabilities:
            severity_text = vuln['severity_level'].lower()

            # 检查每个严重级别关键词
            for severity, keywords in severity_keywords.items():
                for keyword in keywords:
                    # 使用正则表达式确保匹配完整单词
                    if re.search(r'\b' + keyword + r'\b', severity_text):
                        severity_count[severity] += 1
                        break

    return severity_count


def conclude_repo_report():
    """
    生成扫描报告的总结部分，包括漏洞和许可证风险评估以及引入建议
    """
    # TODO: 生成扫描报告的总结部分，包括漏洞和许可证风险评估以及引入建议


def conclude_pkg_report():
    """
    生成软件包扫描报告的总结部分，包括漏洞和许可证风险评估以及引入建议
    """
    # TODO: 生成软件包扫描报告的总结部分，包括漏洞和许可证风险评估以及引入建议

def replace_placeholders():
    """
    替换文档中的占位符为实际内容
    """
    # TODO: 替换文档中的占位符为实际内容
