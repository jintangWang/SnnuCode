import pandas as pd
import matplotlib.pyplot as plt
import os

# 设置全局字体
plt.rcParams.update({
    'font.family': 'Times New Roman',
    'font.size': 10,
    'axes.titlesize': 14,
    'axes.labelsize': 12,
    'legend.fontsize': 15,  # 增大图例字体
})

# 第一组图（前4个）
fig1, axes1 = plt.subplots(2, 2, figsize=(12, 12))
plt.subplots_adjust(hspace=0.3, wspace=0.3)  # 减小行间距

# 第二组图（后4个）
fig2, axes2 = plt.subplots(2, 2, figsize=(12, 12))
plt.subplots_adjust(hspace=0.3, wspace=0.3)  # 减小行间距

# 分成两组文件
files_group1 = [
    ('1setup-data.csv', 'Setup Time'),
    ('2enkeygen-data.csv', 'Encryption Key Generation Time'),
    ('3dekeyGen-data.csv', 'Decryption Key Generation Time'),
    ('4encrypt-data.csv', 'Encryption Time')
]

files_group2 = [
    ('5verify-data.csv', 'Verify Time'),
    ('6search-data.csv', 'Search Time'),
    ('7transform-data.csv', 'Transform Time'),
    ('8dec-data.csv', 'Decryption Time')
]

# Define colors and markers for different schemes
styles = {
    'Ours': ('-', 'o', 'blue'),
    'DP-ABE': ('--', '^', 'orange'),
    'CFDS': (':', 's', 'green'),
    'MIBE': ('-.', 'D', 'red'),
    'CP-ABE': ('--', 'v', 'purple'),
    'KSF-OABE': ('--', '*', 'brown')  # 添加缺失的方案
}

current_dir = os.path.dirname(os.path.abspath(__file__))


# 处理第一组图
for idx, (file_name, title) in enumerate(files_group1):
    row = idx // 2
    col = idx % 2
    ax = axes1[row, col]
    
    try:
        # Read CSV data and print first column for debugging
        data = pd.read_csv(os.path.join(current_dir, file_name))
        print(f"\nFile: {file_name}")
        print("Schemes in CSV:", data.iloc[:, 0].values)
        
        # Get schemes from first column (excluding header)
        schemes = data.iloc[:, 0].values
        
        # Strip whitespace and handle potential encoding issues
        schemes = [str(s).strip() for s in schemes]
        print("Processed schemes:", schemes)
        
        # Create x range based on actual data columns
        x_range = range(4, 4 + len(data.columns) - 1)
        
        # Plot each scheme's data
        for scheme in schemes:
            # Debug print for each scheme
            print(f"Processing scheme: '{scheme}'")
            if scheme in styles:
                print(f"Found style for: {scheme}")
                scheme_data = data[data.iloc[:, 0].str.strip() == scheme]
                if not scheme_data.empty:
                    values = scheme_data.iloc[0, 1:].values
                    line_style, marker, color = styles[scheme]
                    ax.plot(x_range, values,
                           label=scheme,
                           linestyle=line_style,
                           marker=marker,
                           color=color,
                           markersize=4)
                else:
                    print(f"No data found for scheme: {scheme}")

        # Customize subplot with adjusted parameters
        ax.set_title(f"({chr(97+idx)}) {title}", pad=10, fontsize=14, fontfamily='Times New Roman')
        ax.grid(True, alpha=0.3)  # 降低网格线透明度
        ax.set_xlabel("Size of Attributes", fontsize=12, fontfamily='Times New Roman')
        ax.set_ylabel("Runtime (ms)", fontsize=12, fontfamily='Times New Roman')
        ax.tick_params(axis='both', labelsize=12)  # 调整刻度标签大小
        ax.legend(loc="upper left", fontsize=13, framealpha=0.7, 
                 bbox_to_anchor=(0.02, 0.98))  # 调整图例位置和大小
        
    except Exception as e:
        print(f"Error processing {file_name}: {str(e)}")
        continue  # 继续处理下一个文件

# 处理第二组图
for idx, (file_name, title) in enumerate(files_group2):
    row = idx // 2
    col = idx % 2
    ax = axes2[row, col]
    
    try:
        # Read CSV data and print first column for debugging
        data = pd.read_csv(os.path.join(current_dir, file_name))
        print(f"\nFile: {file_name}")
        print("Schemes in CSV:", data.iloc[:, 0].values)
        
        # Get schemes from first column (excluding header)
        schemes = data.iloc[:, 0].values
        
        # Strip whitespace and handle potential encoding issues
        schemes = [str(s).strip() for s in schemes]
        print("Processed schemes:", schemes)
        
        # Create x range based on actual data columns
        x_range = range(4, 4 + len(data.columns) - 1)
        
        # Plot each scheme's data
        for scheme in schemes:
            # Debug print for each scheme
            print(f"Processing scheme: '{scheme}'")
            if scheme in styles:
                print(f"Found style for: {scheme}")
                scheme_data = data[data.iloc[:, 0].str.strip() == scheme]
                if not scheme_data.empty:
                    values = scheme_data.iloc[0, 1:].values
                    line_style, marker, color = styles[scheme]
                    ax.plot(x_range, values,
                           label=scheme,
                           linestyle=line_style,
                           marker=marker,
                           color=color,
                           markersize=4)
                else:
                    print(f"No data found for scheme: {scheme}")

        # Customize subplot with adjusted parameters
        ax.set_title(f"({chr(97+idx+4)}) {title}", pad=10, fontsize=14, fontfamily='Times New Roman')
        ax.grid(True, alpha=0.3)  # 降低网格线透明度
        ax.set_xlabel("Size of Attributes", fontsize=12, fontfamily='Times New Roman')
        ax.set_ylabel("Runtime (ms)", fontsize=12, fontfamily='Times New Roman')
        ax.tick_params(axis='both', labelsize=12)  # 调整刻度标签大小
        ax.legend(loc="upper left", fontsize=13, framealpha=0.7, 
                 bbox_to_anchor=(0.02, 0.98))  # 调整图例位置和大小
        
    except Exception as e:
        print(f"Error processing {file_name}: {str(e)}")
        continue  # 继续处理下一个文件

# 保存两个图
plt.figure(fig1.number)
plt.savefig('combined_plots_part1.png', dpi=300, bbox_inches='tight', pad_inches=0.2)

plt.figure(fig2.number)
plt.savefig('combined_plots_part2.png', dpi=300, bbox_inches='tight', pad_inches=0.2)

plt.show()
