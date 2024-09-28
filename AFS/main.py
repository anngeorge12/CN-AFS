import numpy as np
import pandas as pd
import joblib
import sklearn as sk
import matplotlib.pyplot as plt
import scapy
import pyshark
df = pd.read_csv('cicids_2017.csv')

# Check the first few rows
#print(df.head())
# Check for null values
#print(df.isnull().sum())

# Display the columns in the dataset
#print(df.columns)

# Columns to be dropped
columns_to_drop = [
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# Drop the specified columns from the DataFrame
df = df.drop(columns=columns_to_drop, axis=1)

# Verify the remaining columns
#print(df.columns)
# Convert all attack types to 'Malicious' and label Benign as 0, Malicious as 1
df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

# Check the distribution of labels
#print(df['Label'].value_counts())
# Fill missing numerical values with the mean of the respective column
df = df.fillna(df.mean())

# Verify that no missing values remain
#print(df.isnull().sum())
#----------------------------------------------------------------------------------------#


#---------------Standardisation and Normalisation of the Features----------------------#

from sklearn.preprocessing import StandardScaler

# Step 1: Replace infinite values with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Step 2: Fill NaN values with the mean of the respective column
df.fillna(df.mean(), inplace=True)

# Step 3: Check that no infinite or NaN values remain
#print(np.isinf(df).sum())  # Should print 0 for all columns
#print(df.isnull().sum())   # Should print 0 for all columns

# Step 4: Split features and labels
X = df.drop('Label', axis=1)
y = df['Label']

# Step 5: Scale the features using StandardScaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
# Save the scaler
joblib.dump(scaler, 'scaler.pkl')

# Check the scaled feature values
#print(X_scaled[:5])  # Display the first 5 rows of scaled data
#---------------------------------------------------------------------#
from sklearn.model_selection import train_test_split

# Split the dataset into training and testing sets (70% train, 30% test)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

# Check the shape of the split data
#print(X_train.shape, X_test.shape)
#=-----------------------------------------------------------#
from sklearn.ensemble import RandomForestClassifier

# Train a Random Forest model to get feature importance
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

# Get the importance of each feature
feature_importances = clf.feature_importances_

# Create a DataFrame of feature names and their importance scores
feature_importance_df = pd.DataFrame({
    'Feature': X.columns,
    'Importance': feature_importances
})

# Sort by importance
feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False)

# Display the top 10 most important features
#print(feature_importance_df.head(10))

#---Accuracy Check---------#
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_auc_score, roc_curve

y_pred = clf.predict(X_test)

# Step 4: Calculate and print the accuracy score
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy * 100:.2f}%")
print(f"Accuracy: {accuracy * 100:.2f}%")
#-----------loading the created model-----------#
joblib.dump(clf, 'firewall_model.pkl')

# Save the preprocessed dataset
preprocessed_data = pd.concat([pd.DataFrame(X_scaled, columns=X.columns), y.reset_index(drop=True)], axis=1)
preprocessed_data.to_csv('preprocessed_cicids.csv', index=False)

# Check the saved file
print(preprocessed_data.head())



