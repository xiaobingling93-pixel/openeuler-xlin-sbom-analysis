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

class Package:
    def __init__(self, name: str, version: str, release: str):
        self.name = name
        self.version = version
        self.release = release
        self.license = ""
        self.categories = set()
        self.vulnerabilities = []
        self.files = []
        self.dependencies = []
        self.scan_result = {}

    def add_category(self, category: str) -> None:
        """
        添加许可证类别到软件包的类别集合中

        Args:
            category (str): 要添加的许可证类别名称

        Returns:
            None: 直接修改对象的categories属性，不返回任何值
        """

        self.categories.add(category)

    def add_vulnerability(self, id: str, severity_type: str, severity_level: str, fixed: str) -> None:
        """
        向软件包添加漏洞信息，避免重复添加相同ID的漏洞

        Args:
            id (str): 漏洞唯一标识符（如CVE编号）
            severity_type (str): 漏洞评分类型（如CVSS）
            severity_level (str): 漏洞评分等级和分数
            fixed (str): 漏洞的修复版本信息

        Returns:
            None: 直接修改对象的vulnerabilities属性，不返回任何值
        """

        if any(vuln['id'] == id for vuln in self.vulnerabilities):
            return

        vulnerability = {
            "id": id,
            "severity_type": severity_type,
            "severity_level": severity_level,
            "fixed": fixed
        }
        self.vulnerabilities.append(vulnerability)

    def add_license(self, license: str) -> None:
        """
        设置软件包的许可证信息

        Args:
            license (str): 软件包的许可证名称或表达式

        Returns:
            None: 直接修改对象的license属性，不返回任何值
        """

        self.license = license

    def add_file(self, file: dict) -> None:
        """
        向软件包添加单个文件信息

        Args:
            file (dict): 包含文件信息的字典，通常包含文件名、路径、许可证等信息

        Returns:
            None: 直接修改对象的files属性，不返回任何值
        """

        self.files.append(file)

    def append_files(self, files: list) -> None:
        """
        向软件包批量添加多个文件信息

        Args:
            files (list): 包含多个文件信息字典的列表

        Returns:
            None: 直接修改对象的files属性，不返回任何值
        """

        self.files.extend(files)

    def add_dependency(self, dependency: object) -> None:
        """
        向软件包添加依赖项

        Args:
            dependency (Package): 依赖项的Package对象

        Returns:
            None: 直接修改对象的dependencies属性，不返回任何值
        """

        self.dependencies.append(dependency)

    def set_scan_result(self, result: str, summary: list) -> None:
        """
        设置软件包的扫描结果信息

        Args:
            result (str): 扫描的总体结果，如"同意引入"或"拒绝引入"
            summary (list): 扫描结果摘要信息列表，包含各项风险评估的总结

        Returns:
            None: 直接修改对象的scan_result属性，不返回任何值
        """

        self.scan_result = {
            "result": result,
            "summary": summary
        }
