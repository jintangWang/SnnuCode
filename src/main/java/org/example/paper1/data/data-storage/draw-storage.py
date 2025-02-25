import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

# 获取当前文件所在目录路径
current_dir = os.path.dirname(os.path.abspath(__file__))

# 读取三个CSV文件，使用正确的相对路径
bac_pe_data = pd.read_csv(os.path.join(current_dir, '../data-storage/bac_pe_storage_data.csv'))
cfds_data = pd.read_csv(os.path.join(current_dir, '../data-storage/cfds_storage_data.csv'))
ksf_oabe_data = pd.read_csv(os.path.join(current_dir, '../data-storage/ksf_oabe_storage_data.csv'))

# 设置全局字体
plt.rcParams.update({
    'font.family': 'Times New Roman',
    'font.size': 10,
    'axes.titlesize': 14,
    'axes.labelsize': 12,
    'legend.fontsize': 15,  # 增大图例字体
})

# 设置图形大小和布局
fig, axs = plt.subplots(2, 2, figsize=(12, 12))  # 减小图形整体宽度
plt.subplots_adjust(hspace=0.3, wspace=0.3)

# 选择要对比的属性数量点（例如选择10, 20, 30, 40, 50）
attr_points = [10, 20, 30, 40, 50]

# 定义方案名称和颜色
schemes = ['Ours', 'CFDS', 'KSF-OABE']  # 将 'BAC-PE' 改为 'Ours'
colors = ['blue', 'orange', 'green']

# 组件名称
components = ['SystemParams', 'EncryptionKey', 'DecryptionKey', 'Ciphertext']

# 为每个组件创建柱状图
for idx, component in enumerate(components):
    row = idx // 2
    col = idx % 2
    ax = axs[row, col]
    
    # 获取每个方案在选定属性点的存储大小
    x = np.arange(len(attr_points))
    width = 0.25  # 柱的宽度
    
    # 绘制每个方案的柱状图
    for i, (scheme, color) in enumerate(zip(schemes, colors)):
        if scheme == 'Ours':  # 修改条件判断
            data = bac_pe_data
        elif scheme == 'CFDS':
            data = cfds_data
        else:
            data = ksf_oabe_data
            
        values = [data[data['Component'] == component][str(point)].values[0] for point in attr_points]
        ax.bar(x + (i-1)*width, values, width, label=scheme, color=color, alpha=0.8)
    
    # 设置图形属性
    ax.set_title(f'({chr(97+idx)}) {component}', pad=10, fontfamily='Times New Roman')
    ax.set_xticks(x)
    ax.set_xticklabels(attr_points)
    ax.set_xlabel('Number of Attributes', fontfamily='Times New Roman')
    ax.set_ylabel('Storage Size (bytes)', fontfamily='Times New Roman')
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper left", fontsize=15, framealpha=0.7,
             bbox_to_anchor=(0.02, 0.98))  # 调整图例位置和大小

# 保存图片时调整边距
plt.tight_layout()  # 自动调整边距
output_path = os.path.join(current_dir, 'storage_comparison.png')
plt.savefig(output_path, dpi=300)  # 移除 bbox_inches 参数
plt.show()
