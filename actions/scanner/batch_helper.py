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

def _scan_source_code(type_, path, dep_scan_file, config, max_workers, disable_tqdm):
    """
    根据给定的类型和路径，扫描源代码并返回文件列表。
    """


def _process_dependencies(package, dependencies_data, config):
    """
    处理依赖项数据，并将它们作为依赖项添加到主 Package 对象中。
    """


def _add_vulnerabilities_to_package(package, config):
    """
    查询 OSV 漏洞并将其添加到 Package 对象中。返回原始漏洞数据以便保存。
    """


def _print_summary_table(packages):
    """
    打印软件包扫描结果的汇总表格
    """

def _process_package_from_row(row, args, formatted_utc_time, config):
    """
    处理从CSV文件读取的单行数据（一个软件包）。
    """


def scan_batch(args, formatted_utc_time, config):
    """
    批量扫描多个软件包，生成安全引入评估报告。
    """
