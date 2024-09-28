import pandas as pd

# Load the new dataset from the PCAP file
df_new = pd.read_csv('processed_traffic.csv')

# Load the preprocessed dataset used for training (which should have the correct features)
df_train = pd.read_csv('preprocessed_cicids.csv')

# Get the list of columns used during model training
train_features = df_train.columns

# Check for missing columns in the new dataset
missing_columns = set(train_features) - set(df_new.columns)
extra_columns = set(df_new.columns) - set(train_features)

# Print the differences
print("Missing columns in the new dataset:", missing_columns)
print("Extra columns in the new dataset:", extra_columns)

# If there are missing columns, handle them (e.g., add with default values)
for col in missing_columns:
    df_new[col] = 0  # Assuming a default value of 0, adjust as needed

# Align columns in the same order as the training data
df_new = df_new[train_features]

# Save the updated dataframe (just for verification)
df_new.to_csv('aligned_pcap_extracted_features.csv', index=False)
