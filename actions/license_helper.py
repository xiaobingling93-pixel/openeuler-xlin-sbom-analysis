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


# 定义四大种类许可证的引入建议
LICENSE_TYPE_ADVICE = {
    "permissive": "宽松许可证、公共领域属于宽松型许可证。核心义务是保留原始版权和许可声明。建议在使用的代码文件中明确保留原始版权声明和许可文本，分发时须附带原始许可证副本，并注意兼容性约束。",
    "restricted": "有限著佐权许可证、受限免费许可证属于限制型许可证。建议通过动态链接或服务化隔离核心代码，明确区分派生作品与独立模块，对修改部分进行详细记录并开源，避免静态链接或代码混合。",
    "copyleft": "著佐权许可证属于强制型许可证。建议采用微服务或容器化架构隔离核心传染性组件，通过明确的API边界降低传染风险，动态链接替代静态链接，独立发布修改部分并公开源代码。",
    "special": "商业许可证、专有免费许可证、源码可见、贡献者许可协议、专利许可证、未声明许可证属于特殊型许可证。建议建立合规跟踪机制，明确贡献者版权归属，签署CLA或专利授权协议，避免未明确许可的代码集成。"
}

# 构建许可证类别详细信息列表
LICENSE_CATEGORY_DETAILS = [
    {
        "scancode_category": "CLA",
        "description": "贡献者许可协议 (Contributor License Agreement - CLA)：该许可证描述和定义了软件项目持续开发和增强过程中接受贡献的规则。CLA 可能规定最终的软件贡献本身将如何被授权许可。",
        "suggestion": LICENSE_TYPE_ADVICE["special"]
    },
    {
        "scancode_category": "Commercial",
        "description": "商业许可证 (Commercial)​：供应商和客户之间根据直接的商业许可协议提供的第三方专有软件。如无商业采购合同，贸然使用可能存在法律风险。",
        "suggestion": LICENSE_TYPE_ADVICE["special"]
    },
    {
        "scancode_category": "Copyleft",
        "description": "著佐权许可证 (Copyleft)​：采用'著佐权 (Copyleft)'许可的开源软件，授予公众不可撤销的复制和以相同或修改形式再分发作品的权限，但条件是所有此类再分发必须以便于进一步修改的形式提供作品，并使用相同的许可条款。著佐权许可要求与著佐权许可代码交互的代码也以相同方式获得许可（'传染性'）。",
        "suggestion": LICENSE_TYPE_ADVICE["copyleft"]
    },
    {
        "scancode_category": "Copyleft Limited",
        "description": "有限著佐权许可证 (Copyleft Limited)​：要求再分发源代码（包括修改）并为软件作者提供归属声明的许可证。再分发源代码（包括与此许可下的代码链接的专有代码）的义务，根据特定许可的规则受到限制。",
        "suggestion": LICENSE_TYPE_ADVICE["restricted"]
    },
    {
        "scancode_category": "Free Restricted",
        "description": "受限免费许可证 (Free Restricted)​：一种宽松式 (Permissive-style) 许可，但包含对软件使用（例如，软件不打算用于核电站）或软件再分发（例如，未经明确许可不得进行软件商业再分发）的限制。",
        "suggestion": LICENSE_TYPE_ADVICE["restricted"]
    },
    {
        "scancode_category": "Patent License",
        "description": "专利许可证 (Patent License)​：一种适用于专利而非特定软件的许可证。可以与适用于软件组件的其他软件许可证结合使用。",
        "suggestion": LICENSE_TYPE_ADVICE["special"]
    },
    {
        "scancode_category": "Permissive",
        "description": "宽松许可证 (Permissive)​：在'非著佐权 (non-copyleft)'许可下提供的开源软件。这类许可证通常要求对所包含的开源代码进行归属声明，并可能包含其他义务。",
        "suggestion": LICENSE_TYPE_ADVICE["permissive"]
    },
    {
        "scancode_category": "Proprietary Free",
        "description": "专有免费许可证 (Proprietary Free)​：可能不需要商业许可但可能有特定条款和条件的专有免费软件，产品团队有义务遵守这些条款和条件。其中一些条款和条件随代码提供、或在代码中包含、或出现在可点击下载的许可证中。",
        "suggestion": LICENSE_TYPE_ADVICE["special"]
    },
    {
        "scancode_category": "Public Domain",
        "description": "公共领域 (Public Domain)​：没有明确义务即可使用的开源软件，但根据组织政策，必须随代码保留其许可证声明。该匹配可能适用于软件、网站上的代码示例、已发布的公共领域规范或其他类型的出版物。",
        "suggestion": LICENSE_TYPE_ADVICE["permissive"]
    },
    {
        "scancode_category": "Source-available",
        "description": "源码可见 (Source-available)​：源码可见软件是通过源代码分发模式发布的软件，其安排允许查看源代码，某些情况下也允许修改，但不一定满足称为开源软件的标准。",
        "suggestion": LICENSE_TYPE_ADVICE["special"]
    },
    {
        "scancode_category": "Unstated License",
        "description": "未声明许可证 (Unstated License)​：具有版权声明但未明确声许可条款的第三方软件。常见示例包括来自出版物和网站的代码片段。",
        "suggestion": LICENSE_TYPE_ADVICE["special"]
    }
]

def _load_license_map():
    """
    加载许可证映射关系到全局LICENSE_MAP字典中
    """
    # TODO: 从文件中加载许可证映射关系到全局变量中


def _standardize_license_name():
    """
    将提供的许可名称标准化为 SPDX 标准名称。
    """
    # TODO: 使用标准名称映射关系将提供的名称映射为标准名称


def split_license():
    """
    拆分复合许可证字符串为单个许可证列表
    """
    # TODO: 使用正则表达式将提供的字符串拆分为单个许可证名称


def get_license_category():
    """
    获取许可证的类别
    """
    # TODO: 使用许可证数据集获取许证的类别


def filter_licenses():
    """
    过滤掉许可证列表中包含'unknown'或'non-standard'等条目（不区分大小写）
    """
    # TODO: 过滤掉包含'unknown'或'non-standard'的许可证


def count_licenses():
    """
    统计许可证出现次数并转换为摘要格式
    """
    # TODO: 统计许可证出现的次数并转换为摘要格式


def licenses_visualization():
    """
    生成许可证分布的饼图可视化图表并保存到文件
    """
    # TODO: 使用 Matplotlib 生成饼图可视化图表并保存到文件