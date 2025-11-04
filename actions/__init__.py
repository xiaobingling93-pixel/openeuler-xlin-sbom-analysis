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
import sys

# 检查是否是打包后的环境
if hasattr(sys, '_MEIPASS'):
    PARENT_DIR = sys._MEIPASS  # 生产环境
    LOG_DIR = os.path.expanduser("~/.xlin-sbom-analysis/log/")
else:
    PARENT_DIR = os.path.abspath(os.path.join(
        os.path.dirname(__file__), os.pardir))  # 开发环境
    LOG_DIR = os.path.join(PARENT_DIR, 'log')

ASSIST_DIR = os.path.join(PARENT_DIR, 'assist')
