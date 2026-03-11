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


import tempfile
import os
import shutil
import logging
from fnmatch import fnmatch

def _extract_src_rpm(src_rpm_path):
    """
    解压 .src.rpm 文件并提取其中的源代码压缩文件，返回解压后的源代码目录路径。

    Args:
        src_rpm_path (str): .src.rpm 文件的路径。

    Returns:
        str: 解压后的源代码目录路径。

    Raises:
        ValueError: 如果未在 .src.rpm 文件中找到源代码压缩文件。
    """

    import libarchive

    # 创建一个临时目录用于解压 .src.rpm 文件
    temp_dir = tempfile.mkdtemp()

    try:
        # 解压 .src.rpm 文件
        with libarchive.file_reader(src_rpm_path) as archive:
            for entry in archive:
                pathname = os.path.join(temp_dir, entry.pathname)
                if entry.isdir:
                    os.makedirs(pathname, exist_ok=True)
                elif entry.isfile:
                    parent_dir = os.path.dirname(pathname)
                    os.makedirs(parent_dir, exist_ok=True)
                    with open(pathname, 'wb') as f:
                        for block in entry.get_blocks():
                            f.write(block)

        # 在解压后的文件中查找源代码压缩文件
        source_archive = None
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith(('.tar.xz', '.tar.gz', '.tgz', '.tar.bz2')):
                    source_archive = os.path.join(root, file)
                    break
            if source_archive:
                break

        if not source_archive:
            raise ValueError("未在 .src.rpm 文件中找到源代码压缩文件")

        # 创建一个临时目录用于解压源代码压缩文件
        source_dir = tempfile.mkdtemp()

        # 解压源代码压缩文件
        with libarchive.file_reader(source_archive) as archive:
            for entry in archive:
                pathname = os.path.join(source_dir, entry.pathname)
                if entry.isdir:
                    os.makedirs(pathname, exist_ok=True)
                elif entry.isfile:
                    parent_dir = os.path.dirname(pathname)
                    os.makedirs(parent_dir, exist_ok=True)
                    with open(pathname, 'wb') as f:
                        for block in entry.get_blocks():
                            f.write(block)

        # 返回解压后的源代码目录路径
        return source_dir

    finally:
        # 清理 .src.rpm 的临时目录
        shutil.rmtree(temp_dir)


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

    Args:
        member_path (str): 文件系统的路径，指向需要处理的文件。

    Returns:
        dict or None: 包含文件信息的字典，如果处理失败则返回None。字典包含以下字段：
            - name (str): 处理后的文件路径
            - license (str): 检测到的SPDX许可证表达式
            - holders (list of str): 版权持有者列表
    """

    from scancode import api as scancode
    import traceback

    try:
        licenses = scancode.get_licenses(
            location=member_path, include_text=True)
        copyright_data = scancode.get_copyrights(location=member_path)

        detected_license_expression_spdx = licenses.get(
            'detected_license_expression_spdx')
        holders = list(set(item['holder']
                           for item in copyright_data.get('holders', [])))

        # 处理 member_path
        parts = member_path.split('/')
        if parts[0] == '':
            new_parts = [''] + parts[4:]
        else:
            new_parts = parts[3:]
        processed_file_path = '/'.join(new_parts)

        file_info = {
            "name": processed_file_path,
            "license": detected_license_expression_spdx,
            "holders": holders
        }

        return file_info
    except Exception as e:
        logging.error(f"处理文件 {member_path} 失败: {e}\n{traceback.format_exc()}")
        return None



def scan_src_dir(source_dir, output_file, include, exclude, workers, disable_tqdm):
    """
    扫描源代码目录，提取文件的许可证和版权信息，并进行依赖项扫描。
    """


def scan_src_rpm(src_rpm_path, output_file, include, exclude, workers, disable_tqdm):
    """
    扫描 .src.rpm 文件，提取其中的源代码并进行许可证和依赖项分析。
    """
