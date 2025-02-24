# create_model.py
from sklearn.linear_model import LogisticRegression
import joblib
import numpy as np

X_train = np.random.rand(100, 10)  # 100 samples, 10 features (compatible with n_features: 10 in config.yaml)
y_train = np.random.randint(0, 2, 100)  # Classes 0 or 1
model = LogisticRegression()
model.fit(X_train, y_train)

model_path = "C:\\Users\\mur4t\\Desktop\\ml-pipeline\\model\\model.joblib"
joblib.dump(model, model_path)
print(f"Model saved successfully to: {model_path}")
