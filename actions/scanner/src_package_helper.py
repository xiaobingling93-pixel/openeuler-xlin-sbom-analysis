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


from fnmatch import fnmatch

def _extract_src_rpm(src_rpm_path):
    """
    解压 .src.rpm 文件并提取其中的源代码压缩文件，返回解压后的源代码目录路径。
    """


def _should_include(member_name, include_patterns, exclude_patterns):
    """
    判断一个文件或目录名是否应该被包含在处理范围内。

    Args:
        member_name (str): 文件或目录的名称。
        include_patterns (list): 要包含的文件模式列表（可以为空）。 · 
        exclude_patterns (list): 要排除的文件模式列表（可以为空）。

    Returns:
        bool: 如果文件或目录名符合包含模式且不符合排除模式，则返回True；否则返回False。
    """

    if include_patterns:
        if not any(fnmatch(member_name, pattern) for pattern in include_patterns):
            return False
    if exclude_patterns:
        if any(fnmatch(member_name, pattern) for pattern in exclude_patterns):
            return False
    return True


def _process_member(member_path):
    """
    处理指定的文件成员，提取其许可证、版权信息以及其他元数据。
    """


def scan_src_dir(source_dir, output_file, include, exclude, workers, disable_tqdm):
    """
    扫描源代码目录，提取文件的许可证和版权信息，并进行依赖项扫描。
    """


def scan_src_rpm(src_rpm_path, output_file, include, exclude, workers, disable_tqdm):
    """
    扫描 .src.rpm 文件，提取其中的源代码并进行许可证和依赖项分析。
    """
