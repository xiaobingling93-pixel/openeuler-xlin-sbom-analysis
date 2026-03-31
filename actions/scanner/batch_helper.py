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
import tempfile
import logging
import shutil
import subprocess
from actions.scanner.src_package_helper import (
    scan_src_dir,
    scan_src_rpm
)
from actions.scanner.vulnerability_helper import (
    query_osv_vulnerability,
    process_osv_vuln
)
from actions.license_helper import (
    split_license,
    get_license_category
)
from actions.data_helper import (
    download_file,
    SUPPORTED_ARCHIVES
    )
from actions.package import Package


def _scan_source_code(type_, path, dep_scan_file, config, max_workers, disable_tqdm):
    """
    根据给定的类型和路径，扫描源代码并返回文件列表。

    Args:
        type_ (str): 目标类型，可选值包括 'git', 'src-rpm', 'src', 'url'
        path (str): 目标路径，可以是git仓库URL、文件路径或下载链接
        dep_scan_file (str): 依赖扫描结果文件的路径
        config (dict): 配置对象，包含扫描相关的配置信息
        max_workers (int): 扫描时使用的最大工作线程数
        disable_tqdm (bool): 是否禁用进度条显示

    Returns:
        list: 扫描到的文件列表，每个元素为包含文件信息的字典

    Raises:
        ValueError: 当目标类型无效或文件类型不支持时抛出
        IOError: 当文件下载失败时抛出
        subprocess.CalledProcessError: 当git clone命令执行失败时抛出
    """

    with tempfile.TemporaryDirectory() as temp_dir:
        if type_ == 'git':
            logging.info(f"正在从 {path} 中 clone 源码")
            subprocess.run(['git', 'clone', path, temp_dir],
                           check=True, capture_output=True, text=True)
            return scan_src_dir(temp_dir,
                                dep_scan_file,
                                config.get('batch_scan', {}).get(
                                    'include_file_patterns', []),
                                config.get('batch_scan', {}).get(
                                    'exclude_file_patterns', []),
                                max_workers,
                                disable_tqdm
                                )

        elif type_ == 'src-rpm':
            return scan_src_rpm(path,
                                dep_scan_file,
                                config.get('batch_scan', {}).get(
                                    'include_file_patterns', []),
                                config.get('batch_scan', {}).get(
                                    'exclude_file_patterns', []),
                                max_workers,
                                disable_tqdm
                                )

        elif type_ in ['src', 'url']:
            local_path = path
            if type_ == 'url':
                file_name = os.path.basename(path)
                local_path = os.path.join(temp_dir, file_name)
                logging.info(f"正在从 {path} 下载源码包")
                if not download_file(path, local_path):
                    raise IOError(f"下载文件失败: {path}")

            file_name = os.path.basename(local_path)
            if file_name.endswith('.src.rpm'):
                logging.info(f"处理 SRPM 文件: {file_name}")
                return scan_src_rpm(local_path,
                                    dep_scan_file,
                                    config.get('batch_scan', {}).get(
                                        'include_file_patterns', []),
                                    config.get('batch_scan', {}).get(
                                        'exclude_file_patterns', []),
                                    max_workers,
                                    disable_tqdm
                                    )
            elif any(file_name.endswith(ext) for ext in SUPPORTED_ARCHIVES):
                logging.info(f"解压压缩包: {file_name}")
                unpack_dir = os.path.join(temp_dir, 'unpacked')
                os.makedirs(unpack_dir, exist_ok=True)
                shutil.unpack_archive(local_path, unpack_dir)
                return scan_src_dir(unpack_dir,
                                    dep_scan_file,
                                    config.get('batch_scan', {}).get(
                                        'include_file_patterns', []),
                                    config.get('batch_scan', {}).get(
                                        'exclude_file_patterns', []),
                                    max_workers,
                                    disable_tqdm
                                    )
            else:
                raise ValueError(f"不支持的文件类型: {file_name}")
        else:
            raise ValueError(f"无效的目标类型: {type_}")


def _process_dependencies(package, dependencies_data, config):
    """
    处理依赖项数据，并将它们作为依赖项添加到主 Package 对象中。

    Args:
        package (Package): 主软件包对象，用于添加依赖项
        dependencies_data (dict): 依赖项扫描的原始数据，包含依赖包信息、许可证和漏洞数据
        config (dict): 配置对象，包含处理依赖项相关的配置信息

    Returns:
        None: 该函数直接修改传入的package对象，不返回任何值
    """

    results = dependencies_data.get('results', [])
    dep_pkgs = results[0].get('packages', []) if results else []
    for dep_pkg in dep_pkgs:
        base_info = dep_pkg.get('package', {})
        dep = Package(base_info.get('name'), base_info.get('version'), None)

        dep_licenses_list = dep_pkg.get('licenses', [])
        license_text = ' AND '.join(dep_licenses_list)
        dep.add_license(license_text)

        for license_name in split_license(license_text):
            category = get_license_category(license_name)
            if category and category != "Unknown":
                dep.add_category(category)

        vulns = dep_pkg.get('vulnerabilities', [])
        for vuln in vulns:
            vuln_id, severity_type, severity_level, fixed = process_osv_vuln(
                vuln, dep.name)
            if not config.get('general', {}).get('cve_only') or vuln_id.startswith("CVE"):
                dep.add_vulnerability(
                    vuln_id, severity_type, severity_level, fixed)

        package.add_dependency(dep)


def _add_vulnerabilities_to_package(package, config):
    """
    查询 OSV 漏洞并将其添加到 Package 对象中。返回原始漏洞数据以便保存。

    Args:
        package (Package): 软件包对象，用于添加漏洞信息
        config (dict): 配置对象，包含漏洞处理相关的配置信息，如是否只处理CVE漏洞

    Returns:
        dict or None: 返回从OSV查询到的原始漏洞数据字典，如果未查询到数据则返回None
    """

    osv_data = query_osv_vulnerability(package.name, package.version, config)
    if not osv_data:
        return None

    vulns = osv_data.get("vulns", [])
    for vuln in vulns:
        vuln_id, severity_type, severity_level, fixed = process_osv_vuln(
            vuln, package.name)
        if not config.get('general', {}).get('cve_only') or vuln_id.startswith("CVE"):
            package.add_vulnerability(
                vuln_id, severity_type, severity_level, fixed)
    return osv_data


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
