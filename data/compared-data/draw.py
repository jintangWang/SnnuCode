import pandas as pd
import matplotlib.pyplot as plt

# Load the dataset
file_path = 'setup-data.csv'
data = pd.read_csv(file_path)

# Set up the plot
plt.figure(figsize=(10, 6))

# Define a dictionary for different line styles and markers
line_styles = {
    'Ours': ('-', 'o', 'blue'),  # Solid line with circle marker and blue color
    'DP-ABE': ('-.', '^', 'orange'),  # Dash-dot line with triangle marker and orange color
    'CFDS': ('--', 's', 'yellow')  # Dotted line and square marker with yellow color
}

# Plot the data for each setup
for setup in data['Setup']:
    print(f"Plotting data for setup: {setup}")
    setup_data = data[data['Setup'] == setup]
    sizes = setup_data.iloc[0, 1:].values
    
    # Unpack three values
    linestyle, marker, color = line_styles[setup]
    plt.plot(range(5, 51), sizes, 
            label=setup,
            linestyle=linestyle, 
            marker=marker,
            color=color,
            markersize=6)


# Add title and labels
plt.title("Time for Setup")
plt.xlabel("Size of Attribute Universe")
plt.ylabel("Runtime (ms)")
plt.legend(title="Setup", loc="upper left")

# Show the plot
plt.grid(True)
plt.show()
