import pandas as pd
import matplotlib.pyplot as plt

# Load the dataset
file_path = '3dekeyGen-data.csv'
data = pd.read_csv(file_path)

# Set up the plot
plt.figure(figsize=(10, 6))

# Define colors and markers we can cycle through
colors = ['blue', 'orange', 'green', 'red', 'purple', 'brown', 'pink']
markers = ['o', '^', 's', 'D', 'v', '>', '<']
line_styles = ['-', '--', '-.', ':']

# Get unique algorithm names from first column (excluding header)
algorithms = data.iloc[:, 0].unique()

# Get the actual number of data points
num_points = len(data.columns) - 1  # Subtract 1 for the algorithm name column
x_range = range(4, 4 + num_points)  # Adjust range to match data points

# Plot the data for each algorithm
for idx, algorithm in enumerate(algorithms):
    print(f"Plotting data for algorithm: {algorithm}")
    algo_data = data[data.iloc[:, 0] == algorithm]
    sizes = algo_data.iloc[0, 1:].values
    
    # Cycle through styling options
    color = colors[idx % len(colors)]
    marker = markers[idx % len(markers)]
    line_style = line_styles[idx % len(line_styles)]
    
    plt.plot(x_range, sizes,  # Changed to use x_range
            label=algorithm,
            linestyle=line_style,
            marker=marker,
            color=color,
            markersize=6)

# Add title and labels
plt.title("Time for Decryption Key Generation")
plt.xlabel("Size of Attributes")
plt.ylabel("Runtime (ms)")
plt.legend(loc="upper left")

# Show the plot
plt.grid(True)
plt.show()
