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
import textwrap
from typing import List, Dict
from actions.package import Package
from actions.license_helper import (
    split_license,
    get_license_category,
    LICENSE_CATEGORY_DETAILS,
    SPDX_LICENSES_LIST
)

def _find_non_commercial_licenses(license_summary):
    """
    查找禁止商业用途的许可证

    Args:
        license_summary (list): 许可证摘要信息列表，每个元素为包含许可证信息的字典，
                                通常包含许可证名称等字段

    Returns:
        list: 包含禁止商业用途的许可证列表，每个元素为包含许可证信息的字典
    """

    # 创建SPDX许可证名称（小写）到许可证信息的映射
    spdx_mapping = {}
    for spdx_license in SPDX_LICENSES_LIST:
        key = spdx_license["spdx_name"].lower()
        spdx_mapping[key] = spdx_license

    non_commercial_licenses = []

    for license_info in license_summary:
        license_name = license_info["name"]
        license_key = license_name.lower()

        if license_key in spdx_mapping:
            spdx_info = spdx_mapping[license_key]
            for restriction in spdx_info["cannot"]:
                if restriction["name"].lower() == "commercial use":
                    non_commercial_licenses.append(license_info)
                    break

    return non_commercial_licenses


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


def conclude_repo_report(packages, license_summary, config):
    """
    生成扫描报告的总结部分，包括漏洞和许可证风险评估以及引入建议

    Args:
        packages (list): 软件包列表，每个元素为包含漏洞信息的Package对象
        license_summary (list): 许可证摘要信息列表，每个元素为包含许可证信息的字典
        config (object): 配置对象，包含配置信息

    Returns:
        tuple: 包含三个元素的元组
            - summary (list): 报告摘要信息列表，每个元素为一个总结条目字符串
            - result (str): 评估结果，可能为"同意引入"或"拒绝引入"
            - suggestion (str): 引入建议文本，包含具体的风险处理建议
    """

    vuln_debug = config.get("general", {}).get(
        'debug_mode', {}).get('vulnerability', {})
    license_debug = config.get("general", {}).get(
        'debug_mode', {}).get('license', {})

    # 生成总结部分
    summary = []

    # 漏洞总结
    severity_count = count_vulnerability_severity(packages)

    if vuln_debug.get('enabled') or all(not package.vulnerabilities for package in packages):
        summary.append(f"漏洞风险：未发现已知安全漏洞，安全状态良好")
    else:
        summary.append(
            f"共检测到 {len(packages)} 个软件包存在 "
            f"{severity_count['critical']} 个严重漏洞、"
            f"{severity_count['high']} 个高危漏洞、"
            f"{severity_count['medium']} 个中危漏洞、"
            f"{severity_count['low']} 个低危漏洞。"
        )

    # 许可证总结
    non_commercial_licenses = _find_non_commercial_licenses(license_summary)
    general_license_summary = "具体许可证分析及各类别许可证引入建议详见许可证合规性审查章节。"
    if (not license_debug.get('enabled')) and non_commercial_licenses:
        summary.append(
            f"禁止商业用途许可证风险：检测到 {len(non_commercial_licenses)} 种条款中禁止商业用途的许可证："
            f"{', '.join([license['name'] for license in non_commercial_licenses])}。"
            f"{general_license_summary}"
        )
    else:
        summary.append(
            f"禁止商业用途许可证风险：未发现条款中禁止商业用途的许可证，法律风险较低。"
            f"{general_license_summary}"
        )

    # 获得结论和引入建议
    result = "同意引入"
    suggestion_lines = []

    if (not vuln_debug.get('enabled')) and (
            severity_count.get("critical") > 0 or severity_count.get("high") > 0):
        result = "拒绝引入"
        suggestion_lines.append("存在高危及以上安全漏洞，建议剔除高风险软件包。")
    if (not license_debug.get('enabled')) and non_commercial_licenses:
        result = "拒绝引入"
        suggestion_lines.append(f"存在禁止商业用途的许可证，请考虑其他替代方案。")

    # 构建引入建议文本
    suggestion = "".join(suggestion_lines) if suggestion_lines else "未发现安全风险。"

    return summary, result, suggestion


def replace_placeholders(doc, target_name, start_date, end_date, brief_summary, result, suggestion, config):
    """
    替换文档中的占位符为实际内容

    Args:
        doc (Document): python-docx文档对象，用于替换占位符
        target_name (str): 目标软件包名称
        start_date (str): 扫描开始日期
        end_date (str): 扫描结束日期
        brief_summary (str): 报告摘要信息
        result (str): 评估结果，可能为"同意引入"或"拒绝引入"
        suggestion (str): 引入建议文本
        config (dict): 配置对象，包含作者、审核人等信息

    Returns:
        None: 该函数直接修改传入的doc对象，不返回任何值
    """

    replacements = {
        "@TARGET": textwrap.shorten(target_name, width=70, placeholder="..."),
        "@VERSION": config.get('general', {}).get("report_version", ""),
        "@STARTDATE": start_date,
        "@ENDDATE": end_date,
        "@SUMMARY": brief_summary,
        "@RESULT": result,
        "@SUGGESTION": suggestion,
        "@AUTHOR": config.get('general', {}).get("author", ""),
        "@REVIEWER": config.get('general', {}).get("reviewer", ""),
    }

    # 替换正文段落中的文本
    for para in doc.paragraphs:
        for old_text, new_text in replacements.items():
            if old_text in para.text:
                # 在 run 级别替换以保留格式
                for run in para.runs:
                    if old_text in run.text:
                        run.text = run.text.replace(old_text, new_text)

    # 替换表格中的文本
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    for old_text, new_text in replacements.items():
                        if old_text in para.text:
                            # 在 run 级别替换以保留格式
                            for run in para.runs:
                                if old_text in run.text:
                                    run.text = run.text.replace(
                                        old_text, new_text)

    # 替换页眉和页脚中的文本
    for section in doc.sections:
        # 处理页眉
        if section.header:
            for para in section.header.paragraphs:
                for old_text, new_text in replacements.items():
                    if old_text in para.text:
                        # 在 run 级别替换以保留格式
                        for run in para.runs:
                            if old_text in run.text:
                                run.text = run.text.replace(old_text, new_text)

        # 处理页脚
        if section.footer:
            for para in section.footer.paragraphs:
                for old_text, new_text in replacements.items():
                    if old_text in para.text:
                        # 在 run 级别替换以保留格式
                        for run in para.runs:
                            if old_text in run.text:
                                run.text = run.text.replace(old_text, new_text)

