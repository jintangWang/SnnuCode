import pandas as pd
import matplotlib.pyplot as plt

# 调整图形尺寸和布局参数
plt.rcParams.update({'font.size': 8})  # 减小字体大小
fig, axes = plt.subplots(4, 2, figsize=(12, 24))  # 改为4行2列布局
plt.subplots_adjust(hspace=0.4, wspace=0.3)  # 增加子图间距

# List of CSV files and their titles
files = [
    ('1setup-data.csv', 'Setup Time'),
    ('2enkeygen-data.csv', 'Encryption Key Generation Time'),
    ('3dekeyGen-data.csv', 'Decryption Key Generation Time'),
    ('4encrypt-data.csv', 'Encryption Time'),
    ('5verify-data.csv', 'Verify Time'),
    ('6search-data.csv', 'Search Time'), 
    ('7reenc-data.csv', 'Re-encryption Time'),
    ('8dec-data.csv', 'Decryption Time')
]

# Define colors and markers for different schemes
styles = {
    'Ours': ('-', 'o', 'blue'),
    'DP-ABE': ('--', '^', 'orange'),
    'CFDS': (':', 's', 'green'),
    'MIBE': ('-.', 'D', 'red'),
    'CP-ABE': ('--', 'v', 'purple'),
    'PRE-SE': ('--', '*', 'brown')  # 添加缺失的方案
}

# Plot each subplot
for idx, (file_name, title) in enumerate(files):
    row = idx // 2  # 修改为2列布局
    col = idx % 2
    ax = axes[row, col]
    
    try:
        # Read CSV data and print first column for debugging
        data = pd.read_csv(f'../compared-data/{file_name}')
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
        ax.set_title(f"({chr(97+idx)}) {title}", pad=10, fontsize=10)
        ax.grid(True, alpha=0.3)  # 降低网格线透明度
        ax.set_xlabel("Size of Attributes", fontsize=8)
        ax.set_ylabel("Runtime (ms)", fontsize=8)
        ax.tick_params(axis='both', labelsize=8)  # 调整刻度标签大小
        ax.legend(loc="upper left", fontsize=7, framealpha=0.7)
        
    except Exception as e:
        print(f"Error processing {file_name}: {str(e)}")
        continue  # 继续处理下一个文件

# Adjust layout
plt.tight_layout()
# 保存时确保有足够的边距
plt.savefig('combined_plots.png', dpi=300, bbox_inches='tight', pad_inches=0.2)
plt.show()
