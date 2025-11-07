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
import os
from actions.license_helper import (
    split_license,
    get_license_category
)
from actions.scanner.vulnerability_helper import (
    query_osv_vulnerability,
    process_osv_vuln
)
from actions.data_helper import save_data_to_json
from actions.package import Package
from tqdm import tqdm


def _process_spdx_sbom(sbom, disable_tqdm, data_dir, config):
    """
    处理SPDX格式的SBOM文件，提取软件包信息、许可证信息和漏洞信息

    Args:
        sbom (dict): 从SPDX文件中读取的JSON数据，包含软件包、许可证和依赖关系信息
        disable_tqdm (bool): 是否禁用进度条显示，True表示禁用，False表示启用
        data_dir (str): 数据存储目录路径，用于保存漏洞扫描结果等文件
        config (dict): 配置信息，包含扫描和报告生成所需的各种设置参数

    Returns:
        tuple: 包含两个元素的元组:
            - packages (list): 成功处理的Package对象列表，每个对象包含软件包的名称、版本、许可证、类别和漏洞信息
            - failed_packages (list): 处理失败的软件包信息列表，每个元素为包含name、version和error字段的字典
    """
    
    packages = []
    failed_packages = []
    spdxid_to_package = {}

    for package_data in tqdm(sbom.get('packages', []), desc="Processing packages", disable=disable_tqdm):
        try:
            name = package_data.get("name", "")
            version = package_data.get("versionInfo", "")

            # 创建Package对象
            pkg = Package(name, version, None)

            # 处理许可证信息
            license_concluded = package_data.get("licenseConcluded")
            license_declared = package_data.get("licenseDeclared")

            if license_concluded and license_concluded != "NOASSERTION":
                license_text = license_concluded
            else:
                license_text = license_declared or license_concluded or ""

            license_text = "" if license_text == "NOASSERTION" else license_text

            # 处理LicenseRef引用
            if license_text and license_text.startswith("LicenseRef"):
                for license_info in sbom.get("hasExtractedLicensingInfos", []):
                    if license_info.get("licenseId") == license_text:
                        license_text = license_info.get("name", license_text)
                        break

            # 添加许可证信息
            if license_text:
                pkg.add_license(license_text)

            # 添加许可证类别
            license_list = split_license(license_text)
            for license_name in license_list:
                category = get_license_category(license_name)
                if category and category != "Unknown":
                    pkg.add_category(category)

            # 查询漏洞信息
            osv_vulnerability = query_osv_vulnerability(name, version, config)
            if osv_vulnerability:
                vulns_record = os.path.join(
                    data_dir, f"{name}-{version} 漏洞扫描结果.json")
                save_data_to_json(osv_vulnerability, vulns_record)

            vulns = osv_vulnerability.get(
                "vulns", []) if osv_vulnerability else []
            for vuln in vulns:
                vuln_id, severity_type, severity_level, fixed = process_osv_vuln(
                    vuln, name)
                if not config.get('general', {}).get('cve_only') or (vuln_id and vuln_id.startswith("CVE")):
                    pkg.add_vulnerability(
                        vuln_id, severity_type, severity_level, fixed)

            # 记录SPDXID到Package对象的映射
            spdx_id = package_data.get("SPDXID")
            if spdx_id:
                spdxid_to_package[spdx_id] = pkg

            packages.append(pkg)

        except Exception as e:
            # 记录处理失败的包信息
            failed_packages.append({
                "name": name,
                "version": version,
                "release": None,
                "error": str(e)
            })
            logging.debug(str(e))

    # 处理依赖关系
    for relationship in sbom.get("relationships", []):
        relationship_type = relationship.get("relationshipType")
        spdx_element_id = relationship.get("spdxElementId")
        related_spdx_element = relationship.get("relatedSpdxElement")

        # 只处理DEPENDS_ON和DEPENDENCY_OF关系
        if relationship_type in ["DEPENDS_ON", "DEPENDENCY_OF"]:
            if relationship_type == "DEPENDS_ON":
                # DEPENDS_ON: spdxElementId 依赖于 relatedSpdxElement
                dependent_pkg = spdxid_to_package.get(spdx_element_id)
                dependency_pkg = spdxid_to_package.get(related_spdx_element)

                if dependent_pkg and dependency_pkg:
                    dependent_pkg.add_dependency(dependency_pkg)
                else:
                    if not dependent_pkg:
                        logging.warning(f"未找到SPDXID为 {spdx_element_id} 的包对象")
                    if not dependency_pkg:
                        logging.warning(
                            f"未找到SPDXID为 {related_spdx_element} 的包对象")

            elif relationship_type == "DEPENDENCY_OF":
                # DEPENDENCY_OF: spdxElementId 被 relatedSpdxElement 依赖
                dependency_pkg = spdxid_to_package.get(spdx_element_id)
                dependent_pkg = spdxid_to_package.get(related_spdx_element)

                if dependent_pkg and dependency_pkg:
                    dependent_pkg.add_dependency(dependency_pkg)
                else:
                    if not dependent_pkg:
                        logging.warning(
                            f"未找到SPDXID为 {related_spdx_element} 的包对象")
                    if not dependency_pkg:
                        logging.warning(f"未找到SPDXID为 {spdx_element_id} 的包对象")

    return packages, failed_packages


def scan_sbom():
    """
    扫描SBOM文件并生成安全评估报告
    """
    # TODO: 读取 SBOM 文件并进行漏洞和许可证合规性分析，生成安全评估报告