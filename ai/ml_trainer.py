import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from elasticsearch import Elasticsearch

# Load attack logs from PostgreSQL
df = pd.read_sql("SELECT * FROM attacks", db_conn)

# Feature engineering
df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
df['is_brute_force'] = df['service'].apply(lambda x: 1 if x in ['ssh', 'rdp'] else 0)

# Train model
X = df[['hour', 'is_brute_force']]
y = df['attack_type']  # Labels need to be manually annotated

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save model
import joblib
joblib.dump(model, 'attack_classifier.pkl')

# Export predictions to Elasticsearch
es = Elasticsearch(["http://localhost:9200"])
prediction = {"attack_type": "brute_force", "confidence": 0.95}
es.index(index="ml_predictions", body=prediction)