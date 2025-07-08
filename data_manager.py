# engines/data_manager.py

import pandas as pd
import numpy as np
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.feature_selection import RFE, SelectKBest, f_classif, mutual_info_classif
from sklearn.ensemble import RandomForestClassifier
from sklearn.decomposition import PCA
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split

THREAT_TYPES = ['malware', 'adware', 'ransomware', 'malicious_website']

class DatasetMetadata:
    """Enhanced container for dataset metadata with threat type support"""
    def __init__(self, name, features, labels, label_column, file_path, threat_type=None):
        self.name = name
        self.features = features
        self.labels = labels
        self.label_column = label_column
        self.file_path = file_path
        self.threat_type = threat_type if threat_type in THREAT_TYPES else 'generic'
        self.stats = self._generate_dataset_stats(features, labels)
        self.created_at = datetime.now().isoformat()
        self.version = 1.1
        self.data_hash = self._generate_data_hash(pd.concat([features, labels], axis=1))
        self.pipeline = None
        self.processed_features = None
        self.X_train, self.X_test, self.y_train, self.y_test = None, None, None, None

    def _generate_dataset_stats(self, features, labels):
        stats = {
            'samples': len(features),
            'features': features.shape[1],
            'class_distribution': labels.value_counts().to_dict(),
            'missing_values': features.isna().sum().to_dict(),
            'threat_type': self.threat_type
        }
        if hasattr(labels, 'unique'):
            stats['unique_classes'] = len(labels.unique())
        return stats

    def _generate_data_hash(self, df):
        return hashlib.sha256(pd.util.hash_pandas_object(df).values.tobytes()).hexdigest()

    def split_data(self, test_size=0.4, random_state=42):
        """Split data into train/test sets"""
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.features, self.labels, 
            test_size=test_size, 
            random_state=random_state,
            stratify=self.labels
        )
        return self.X_train, self.X_test, self.y_train, self.y_test

class DataManager:
    """Enhanced data manager with threat type support and improved preprocessing"""
    def __init__(self, audit_logger=None):
        self.datasets = {}
        self.active_dataset = None
        self.audit_logger = audit_logger
        self.logger = logging.getLogger("ML_Engine.DataManager")
        self.threat_type_mapping = {
            'malware': ['exe', 'dll', 'sys', 'scr'],
            'adware': ['js', 'vbs', 'jar'],
            'ransomware': ['encrypted', 'locked'],
            'malicious_website': ['html', 'js', 'php']
        }

    def load_dataset(self, file_path: str, label_column: str, dataset_name: str = None, 
                   threat_type: str = None, security_scan: bool = True) -> bool:
        try:
            if security_scan and not self._validate_security(file_path):
                self.logger.error(f"Security validation failed: {file_path}")
                return False

            dataset_name = dataset_name or Path(file_path).stem
            df = pd.read_csv(file_path)
            
            # Auto-detect threat type if not specified
            if not threat_type:
                threat_type = self._detect_threat_type(file_path, df)

            if label_column not in df.columns:
                raise ValueError(f"Label column '{label_column}' not found in dataset")

            features = df.drop(columns=[label_column])
            labels = df[label_column]

            self.datasets[dataset_name] = DatasetMetadata(
                name=dataset_name,
                features=features,
                labels=labels,
                label_column=label_column,
                file_path=file_path,
                threat_type=threat_type
            )
            
            # Auto-split data
            self.datasets[dataset_name].split_data(test_size=0.4)
            
            self.active_dataset = dataset_name
            self.logger.info(f"✅ Loaded {threat_type} dataset '{dataset_name}' with {len(df)} samples")
            return True

        except Exception as e:
            self.logger.error(f"Dataset load failed: {str(e)}")
            return False

    def _detect_threat_type(self, file_path: str, df: pd.DataFrame) -> str:
        """Detect threat type based on file extension and content"""
        file_ext = Path(file_path).suffix.lower()
        for threat_type, extensions in self.threat_type_mapping.items():
            if file_ext in extensions:
                return threat_type
                
        # Fallback to content analysis
        if any(col in df.columns for col in ['url', 'domain', 'ip']):
            return 'malicious_website'
        return 'generic'

    def preprocess_dataset(self, dataset_name: str = None, strategy: str = 'advanced') -> bool:
        try:
            dataset = self._resolve_dataset(dataset_name)
            if not dataset:
                return False

            # Get appropriate preprocessing pipeline
            pipeline = self._get_preprocessing_pipeline(strategy, dataset.threat_type)
            
            # Fit and transform on training data
            dataset.processed_features = pipeline.fit_transform(dataset.X_train, dataset.y_train)
            
            # Transform test data
            if hasattr(dataset, 'X_test'):
                dataset.X_test_processed = pipeline.transform(dataset.X_test)
                
            dataset.pipeline = pipeline
            self.logger.info(f"✅ Preprocessed dataset '{dataset.name}' with '{strategy}' strategy")
            return True

        except Exception as e:
            self.logger.error(f"Preprocessing failed: {str(e)}")
            return False

    def _get_preprocessing_pipeline(self, strategy: str, threat_type: str) -> Pipeline:
        """Get appropriate preprocessing pipeline based on strategy and threat type"""
        numeric_features = ['int64', 'float64']
        categorical_features = ['object', 'category']
        
        numeric_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])
        
        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='most_frequent')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])
        
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, numeric_features),
                ('cat', categorical_transformer, categorical_features)
            ])
        
        if strategy == 'advanced':
            if threat_type == 'malware':
                return Pipeline([
                    ('preprocessor', preprocessor),
                    ('feature_selection', SelectKBest(score_func=mutual_info_classif, k=30)),
                    ('dim_reduction', PCA(n_components=0.95))
                ])
            elif threat_type == 'adware':
                return Pipeline([
                    ('preprocessor', preprocessor),
                    ('feature_selection', RFE(RandomForestClassifier(n_estimators=50), n_features_to_select=20))
                ])
            else:  # Generic pipeline
                return Pipeline([
                    ('preprocessor', preprocessor),
                    ('feature_selection', SelectKBest(score_func=f_classif))
                ])
        else:  # Basic pipeline
            return Pipeline([
                ('preprocessor', preprocessor)
            ])

    def _validate_security(self, file_path: str) -> bool:
        """Enhanced security validation"""
        try:
            path = Path(file_path)
            if path.suffix.lower() not in ['.csv', '.parquet', '.feather']:
                self.logger.warning("File extension not allowed")
                return False
            if path.stat().st_size > 500 * 1024 * 1024:  # 500MB max
                self.logger.warning("File too large")
                return False
                
            # Check for suspicious content in first few lines
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for _ in range(5):
                    line = f.readline()
                    if any(suspicious in line.lower() for suspicious in ['<script', 'eval(', 'exec(']):
                        return False
            return True
        except Exception as e:
            self.logger.error(f"Security validation failed: {str(e)}")
            return False

    def _resolve_dataset(self, dataset_name: str = None) -> DatasetMetadata:
        name = dataset_name or self.active_dataset
        dataset = self.datasets.get(name)
        if not dataset:
            self.logger.warning(f"Dataset '{name}' not found")
        return dataset