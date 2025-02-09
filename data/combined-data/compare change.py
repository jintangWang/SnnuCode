import matplotlib.pyplot as plt

# Ours data
setup_times_ours = [6, 7, 7, 8, 8]
keygen_times_ours = [164, 290, 430, 562, 671]
encryption_times_ours = [162, 289, 408, 551, 672]
decryption_times_ours = [91, 180, 268, 351, 429]
attribute_counts_ours = [10, 20, 30, 40, 50]

# Yang et al. data
setup_times_yang = [78, 148, 305, 540, 849]
keygen_times_yang = [344, 628, 926, 1228, 1521]
encryption_times_yang = [379, 689, 1016, 1350, 1676]
decryption_times_yang = [181, 337, 500, 673, 828]

# Pratish et al. data
setup_times_pratish = [1288, 3573, 7944, 13950, 21854]
keygen_times_pratish = [519, 1809, 4110, 7068, 10917]
encryption_times_pratish = [160, 334, 476, 633, 790]
decryption_times_pratish = [615, 2301, 5234, 8927, 14612]

# Attribute counts (common for all)
attribute_counts = [10, 20, 30, 40, 50]

# Create a figure for plotting
plt.figure(figsize=(12, 10))

# Plot Setup Times
plt.subplot(2, 2, 1)  # 2x2 grid, position 1
plt.plot(attribute_counts_ours, setup_times_ours, marker='o', color='b', label="Ours (Setup Times)", linestyle='-', markersize=8)
plt.plot(attribute_counts, setup_times_yang, marker='s', color='g', label="Yang et al. (Setup Times)", linestyle='--', markersize=8)
plt.plot(attribute_counts, setup_times_pratish, marker='^', color='r', label="Pratish et al. (Setup Times)", linestyle='-.', markersize=8)
plt.title("Setup Times vs Attribute Count")
plt.xlabel("Attribute Count")
plt.ylabel("Time (ms)")
plt.grid(True)
plt.legend()

# Plot Keygen Times
plt.subplot(2, 2, 2)  # 2x2 grid, position 2
plt.plot(attribute_counts_ours, keygen_times_ours, marker='o', color='b', label="Ours (Keygen Times)", linestyle='-', markersize=8)
plt.plot(attribute_counts, keygen_times_yang, marker='s', color='g', label="Yang et al. (Keygen Times)", linestyle='--', markersize=8)
plt.plot(attribute_counts, keygen_times_pratish, marker='^', color='r', label="Pratish et al. (Keygen Times)", linestyle='-.', markersize=8)
plt.title("Keygen Times vs Attribute Count")
plt.xlabel("Attribute Count")
plt.ylabel("Time (ms)")
plt.grid(True)
plt.legend()

# Plot Encryption Times
plt.subplot(2, 2, 3)  # 2x2 grid, position 3
plt.plot(attribute_counts_ours, encryption_times_ours, marker='o', color='b', label="Ours (Encryption Times)", linestyle='-', markersize=8)
plt.plot(attribute_counts, encryption_times_yang, marker='s', color='g', label="Yang et al. (Encryption Times)", linestyle='--', markersize=8)
plt.plot(attribute_counts, encryption_times_pratish, marker='^', color='r', label="Pratish et al. (Encryption Times)", linestyle='-.', markersize=8)
plt.title("Encryption Times vs Attribute Count")
plt.xlabel("Attribute Count")
plt.ylabel("Time (ms)")
plt.grid(True)
plt.legend()

# Plot Decryption Times
plt.subplot(2, 2, 4)  # 2x2 grid, position 4
plt.plot(attribute_counts_ours, decryption_times_ours, marker='o', color='b', label="Ours (Decryption Times)", linestyle='-', markersize=8)
plt.plot(attribute_counts, decryption_times_yang, marker='s', color='g', label="Yang et al. (Decryption Times)", linestyle='--', markersize=8)
plt.plot(attribute_counts, decryption_times_pratish, marker='^', color='r', label="Pratish et al. (Decryption Times)", linestyle='-.', markersize=8)
plt.title("Decryption Times vs Attribute Count")
plt.xlabel("Attribute Count")
plt.ylabel("Time (ms)")
plt.grid(True)
plt.legend()

# Adjust layout for better spacing
plt.tight_layout()

# Show the plots
plt.show()
