from PIL import Image

# 读取两张图片
img1 = Image.open('combined_plots_part1.png')
img2 = Image.open('combined_plots_part2.png')

# 获取图片尺寸
width1, height1 = img1.size
width2, height2 = img2.size

# 设置负的垂直间距来减少行间距
vertical_gap = -70  # 可以调整这个值来控制间距

# 创建新图片（垂直堆叠）
new_width = max(width1, width2)
new_height = height1 + height2 + vertical_gap  # 减少总高度

# 创建新的空白图片
new_img = Image.new('RGB', (new_width, new_height), 'white')

# 计算粘贴位置（水平居中，垂直方向重叠）
paste_x1 = (new_width - width1) // 2
paste_x2 = (new_width - width2) // 2
paste_y2 = height1 + vertical_gap  # 第二张图片的垂直位置上移

# 粘贴图片
new_img.paste(img1, (paste_x1, 0))
new_img.paste(img2, (paste_x2, paste_y2))

# 保存结果
new_img.save('final_combined_plots.png', 'PNG', quality=95, dpi=(300, 300))
