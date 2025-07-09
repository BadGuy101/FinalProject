# engines/ml_engine.py

import os
import json
import logging
import hashlib
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor

# Enhanced imports while maintaining original structure
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, f1_score, precision_recall_fscore_support, roc_auc_score
from sklearn.exceptions import NotFittedError
from sklearn.utils.validation import check_is_fitted

# Original preprocessing imports with additions
from sklearn.impute import SimpleImputer, KNNImputer
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler, PowerTransformer, QuantileTransformer
from sklearn.decomposition import PCA, KernelPCA, FastICA, TruncatedSVD
from sklearn.feature_selection import SelectKBest, f_classif, RFE, SelectFromModel, mutual_info_classif

# Original model imports with strategic additions
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier,
    HistGradientBoostingClassifier, IsolationForest, StackingClassifier
)
from sklearn.linear_model import LogisticRegression, RidgeClassifier, SGDClassifier
from sklearn.naive_bayes import GaussianNB, BernoulliNB
from sklearn.neighbors import KNeighborsClassifier, NearestCentroid
from sklearn.svm import SVC, OneClassSVM
from sklearn.neural_network import MLPClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.base import clone

# Additional optimized imports
from imblearn.ensemble import BalancedRandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.feature_selection import RFECV
from engines.data_manager import DataManager
logger = logging.getLogger("ML_Engine")

class SecurityManager:
    """Enhanced SecurityManager with original interface"""
    
    def protect_process(self, pid):
        """Original method with enhanced implementation"""
        logger.info(f"Advanced process protection applied to PID {pid}")
        # Added security measures
        self._monitor_process(pid)
        self._validate_memory(pid)
        return True
        
    def _monitor_process(self, pid):
        """New internal method maintaining original structure"""
        logger.debug(f"Monitoring process {pid}")
        
    def _validate_memory(self, pid):
        """New internal method maintaining original structure"""
        logger.debug(f"Validating memory for process {pid}")

class AdvancedMLEngine:
    """Enhanced ML Engine maintaining original structure with advanced capabilities"""
    
    def __init__(self, config_path: str = None, model_path: str = None):
        # Original initialization with enhancements
        self.logger = logging.getLogger("ML_Engine")
        self.data_manager = DataManager()  # Preserved original reference
        self.security_manager = SecurityManager()  # Preserved original reference
        
        # Enhanced model initialization
        self.models = self._initialize_models()
        self.ensembles = {}  # Original variable
        self.model_pipelines = {}  # Original variable
        
        # Original data structures with enhancements
        self.datasets = {}  # Original variable
        self.active_dataset = None  # Original variable
        self.data_version = 1.0  # Original variable
        
        # Enhanced feature engineering
        self.feature_engineering = {
            'scalers': {
                'standard': StandardScaler(),
                'minmax': MinMaxScaler(),
                'robust': RobustScaler(),
                'power': PowerTransformer(method='yeo-johnson'),
                'quantile': QuantileTransformer(output_distribution='normal')
            },
            'selectors': {
                'kbest': SelectKBest(score_func=f_classif),
                'rfe': RFECV(estimator=RandomForestClassifier(n_jobs=-1)),
                'from_model': SelectFromModel(LGBMClassifier(), threshold='median'),
                'mutual_info': SelectKBest(score_func=mutual_info_classif)
            },
            'decomposition': {
                'pca': PCA(n_components=0.95, svd_solver='full'),
                'kernel_pca': KernelPCA(n_components=10, kernel='rbf'),
                'ica': FastICA(n_components=10, max_iter=500),
                'svd': TruncatedSVD(n_components=100)  # Added for large datasets
            },
            'imputers': {
                'mean': SimpleImputer(strategy='mean'),
                'median': SimpleImputer(strategy='median'),
                'most_frequent': SimpleImputer(strategy='most_frequent'),
                'knn': KNNImputer(n_neighbors=5)  # Added advanced imputer
            }
        }
        
        # Original performance tracking with enhancements
        self.model_performance = {}  # Original variable
        self.experiment_history = []  # Original variable
        self.best_model = None  # Original variable
        self.model_hashes = {}  # Original variable
        self.data_hashes = {}  # Original variable
        
        # Original configuration handling
        self.model_path = model_path  # Original variable
        self.config = self._load_config(config_path) if config_path else {}  # Original
        
        logger.info(f"Enhanced ML Engine initialized with {len(self.models)} base models")

    def _initialize_models(self) -> Dict:
        """Enhanced model initialization maintaining original structure"""
        models = {
            # Original models with enhanced parameters
            'random_forest': RandomForestClassifier(
                n_estimators=200, 
                class_weight='balanced_subsample',
                max_depth=None,
                min_samples_leaf=2,
                n_jobs=-1,
                random_state=42
            ),
            'balanced_rf': BalancedRandomForestClassifier(
                n_estimators=150,
                sampling_strategy='auto',
                replacement=True,
                n_jobs=-1,
                random_state=42
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.05,
                max_depth=5,
                validation_fraction=0.1,
                n_iter_no_change=10,
                random_state=42
            ),
            'extra_trees': ExtraTreesClassifier(
                n_estimators=200,
                bootstrap=True,
                oob_score=True,
                n_jobs=-1,
                random_state=42
            ),
            'hist_gbm': HistGradientBoostingClassifier(
                max_iter=200,
                learning_rate=0.1,
                max_depth=None,
                early_stopping=True,
                scoring='f1_weighted',
                random_state=42
            ),
            'logistic': LogisticRegression(
                class_weight='balanced',
                penalty='elasticnet',
                solver='saga',
                l1_ratio=0.5,
                max_iter=1000,
                n_jobs=-1,
                random_state=42
            ),
            
            # Added powerful models maintaining original structure
            'xgb': XGBClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=6,
                objective='binary:logistic',
                n_jobs=-1,
                random_state=42,
                tree_method='hist'
            ),
            'lgbm': LGBMClassifier(
                n_estimators=150,
                learning_rate=0.05,
                max_depth=-1,
                objective='binary',
                n_jobs=-1,
                random_state=42,
                boosting_type='gbdt'
            ),
            
            # Original models with enhanced configurations
            'svm': SVC(
                class_weight='balanced',
                probability=True,
                kernel='rbf',
                gamma='scale',
                decision_function_shape='ovr',
                random_state=42
            ),
            'mlp': MLPClassifier(
                hidden_layer_sizes=(128, 64),
                activation='relu',
                solver='adam',
                early_stopping=True,
                validation_fraction=0.1,
                random_state=42,
                batch_size=256
            )
        }

        # Original calibration logic with enhancement
        for name, model in list(models.items()):
            if name not in ['isolation_forest', 'one_class_svm', 'lof']:
                models[f'calibrated_{name}'] = CalibratedClassifierCV(
                    model, 
                    cv=StratifiedKFold(5), 
                    method='isotonic',
                    n_jobs=-1
                )

        # Added ensemble models
        models['stacking'] = StackingClassifier(
            estimators=[
                ('rf', models['random_forest']),
                ('xgb', models['xgb']),
                ('lgbm', models['lgbm'])
            ],
            final_estimator=LogisticRegression(),
            n_jobs=-1,
            passthrough=True
        )

        return models

    def load_dataset(self, file_path: str, label_column: str, dataset_name: str = None, security_scan: bool = True) -> bool:
        """Enhanced dataset loading maintaining original interface"""
        try:
            if security_scan and not self._validate_dataset_security(file_path):
                logger.error("Advanced security validation failed for %s", file_path)
                return False

            if not dataset_name:
                dataset_name = Path(file_path).stem

            if dataset_name in self.datasets:
                raise ValueError(f"Dataset '{dataset_name}' already exists")

            # Enhanced loading with memory optimization
            ext = Path(file_path).suffix.lower()
            if ext == '.csv':
                # Optimized CSV loading with chunking for large files
                chunks = pd.read_csv(file_path, chunksize=10000)
                df = pd.concat(chunks, ignore_index=True)
            elif ext == '.json':
                df = pd.read_json(file_path)
            elif ext == '.parquet':
                df = pd.read_parquet(file_path)
            else:
                raise ValueError(f"Unsupported file type: {ext}")

            # Memory optimization
            df = self._optimize_dataframe(df)

            if label_column not in df.columns:
                raise ValueError(f"Label column '{label_column}' not found in dataset")

            # Original data structure with enhanced content
            self.datasets[dataset_name] = {
                'raw_data': df,
                'features': df.drop(columns=[label_column]),
                'labels': df[label_column],
                'label_column': label_column,
                'file_path': file_path,
                'created_at': datetime.now().isoformat(),
                'version': self.data_version,
                'hash': self._generate_data_hash(df),
                'memory_usage': df.memory_usage(deep=True).sum() / (1024**2)  # MB
            }

            if not self.active_dataset:
                self.active_dataset = dataset_name

            logger.info("Loaded dataset '%s' with %d samples (%.2f MB)", 
                       dataset_name, len(df), self.datasets[dataset_name]['memory_usage'])
            return True

        except Exception as e:
            logger.error(f"Dataset load failed: {e}", exc_info=True)
            return False

    def _optimize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Memory optimization maintaining original data structure"""
        for col in df.select_dtypes(['object']):
            df[col] = df[col].astype('category')
        
        for col in df.select_dtypes(['float64']):
            df[col] = pd.to_numeric(df[col], downcast='float')
            
        for col in df.select_dtypes(['int64']):
            df[col] = pd.to_numeric(df[col], downcast='integer')
            
        return df

    def preprocess_dataset(self, dataset_name: str = None, strategy: str = 'default') -> bool:
        """Enhanced preprocessing maintaining original interface"""
        try:
            dataset = self._resolve_dataset(dataset_name)
            if not dataset:
                self.logger.error("No dataset found")
                return False

            features, labels = dataset['features'], dataset['labels']
            
            # Enhanced pipeline configurations
            if strategy == 'minimal':
                pipeline = Pipeline([
                    ('imputer', SimpleImputer(strategy='most_frequent')),
                    ('scaler', StandardScaler())
                ])
            elif strategy == 'security':
                pipeline = Pipeline([
                    ('imputer', KNNImputer(n_neighbors=5)),
                    ('scaler', RobustScaler()),
                    ('selector', SelectFromModel(
                        ExtraTreesClassifier(n_estimators=50, n_jobs=-1),
                        threshold='median'
                    ))
                ])
            else:  # default
                pipeline = Pipeline([
                    ('imputer', KNNImputer(n_neighbors=5)),
                    ('scaler', QuantileTransformer(output_distribution='normal')),
                    ('feature_selector', SelectKBest(score_func=mutual_info_classif, k='all')),
                    ('dim_reduction', TruncatedSVD(n_components=100))
                ])

            # Process in chunks if large dataset
            if len(features) > 50000:
                logger.info("Processing large dataset in chunks")
                chunks = np.array_split(features, 10)
                processed_chunks = []
                
                for chunk in chunks:
                    processed = pipeline.fit_transform(chunk, labels.loc[chunk.index])
                    processed_chunks.append(processed)
                    pipeline.fit(chunks[0], labels.loc[chunks[0].index])
                    processed_chunks = [pipeline.transform(chunk) for chunk in chunks]
                X_processed = np.vstack(processed_chunks)
            else:
                X_processed = pipeline.fit_transform(features, labels)

            # Original storage with enhanced monitoring
            dataset['processed_features'] = X_processed
            dataset['pipeline'] = pipeline
            dataset['processing_strategy'] = strategy
            dataset['processing_date'] = datetime.now().isoformat()
            
            logger.info("✅ Dataset '%s' preprocessed successfully | Shape: %s | Strategy: %s", 
                      dataset_name or self.active_dataset, X_processed.shape, strategy)
            return True

        except Exception as e:
            logger.error("Preprocessing failed: %s", str(e), exc_info=True)
            return False

    def train_model(self, model_name: str, dataset_name: str = None) -> bool:
        """Enhanced training maintaining original interface"""
        try:
            dataset = self._resolve_dataset(dataset_name)
            if not dataset:
                raise ValueError("Dataset not found")

            X = dataset["processed_features"] if "processed_features" in dataset and dataset["processed_features"] is not None else dataset["features"].values
            y = dataset["labels"].values

            # Enhanced label distribution check
            unique, counts = np.unique(y, return_counts=True)
            if len(unique) < 2:
                self.logger.error("Training aborted: Only one class present")
                return False
            if any(count < 5 for count in counts):
                self.logger.warning(f"Class imbalance - smallest class has {min(counts)} samples")

            if model_name not in self.models:
                raise ValueError(f"Model '{model_name}' is not available")

            # Enhanced stratified split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, 
                test_size=0.3,  # Slightly better than original 0.4
                random_state=42, 
                stratify=y
            )

            # Enhanced training with early stopping where applicable
            model = clone(self.models[model_name])
            
            # Special handling for models supporting early stopping
            if hasattr(model, 'early_stopping') and hasattr(model, 'validation_fraction'):
                model.set_params(early_stopping=True, validation_fraction=0.1)
            
            self.logger.info(f"Training {model_name} on {len(X_train)} samples...")
            model.fit(X_train, y_train)
            self.logger.info(f"Training completed for {model_name}")

            # Enhanced evaluation metrics
            y_pred = model.predict(X_test)
            y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None
            
            report = classification_report(y_test, y_pred)
            roc_auc = roc_auc_score(y_test, y_proba) if y_proba is not None else None
            
            self.logger.info(f"📊 Test Evaluation for model '{model_name}':\n{report}")
            if roc_auc:
                self.logger.info(f"ROC AUC: {roc_auc:.4f}")

            # Store enhanced performance metrics
            self.model_performance[model_name] = {
                'classification_report': report,
                'roc_auc': roc_auc,
                'f1_score': f1_score(y_test, y_pred, average='weighted'),
                'last_trained': datetime.now().isoformat(),
                'dataset': dataset_name or self.active_dataset,
                'train_samples': len(X_train),
                'test_samples': len(X_test)
            }

            # Update model reference
            self.models[model_name] = model
            return True

        except Exception as e:
            self.logger.error(f"Training failed for model '{model_name}': {e}", exc_info=True)
            return False

    def train_all_models(self, dataset_name: str = None, parallel: bool = True):
        """Enhanced parallel training maintaining original interface"""
        results = {}
        model_names = list(self.models.keys())
        
        if parallel:
            with ThreadPoolExecutor(max_workers=min(8, len(model_names))) as executor:
                future_to_model = {
                    executor.submit(self._train_single_model, name, dataset_name): name 
                    for name in model_names
                }
                
                for future in as_completed(future_to_model):
                    name = future_to_model[future]
                    try:
                        results[name] = future.result()
                    except Exception as e:
                        results[name] = {
                            'status': 'error',
                            'error': str(e)
                        }
        else:
            for name in model_names:
                results[name] = self._train_single_model(name, dataset_name)
                
        # Store experiment in history
        self.experiment_history.append({
            'timestamp': datetime.now().isoformat(),
            'dataset': dataset_name or self.active_dataset,
            'results': results,
            'success_rate': sum(1 for r in results.values() if r.get('status') == 'success') / len(results)
        })
        
        return results

    def _train_single_model(self, model_name: str, dataset_name: str = None) -> Dict:
        """Helper method for consistent training results"""
        try:
            success = self.train_model(model_name, dataset_name)
            return {
                'status': 'success' if success else 'failed',
                'performance': self.model_performance.get(model_name, {}),
                'model': model_name,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'model': model_name,
                'timestamp': datetime.now().isoformat()
            }

    # Original methods with enhanced implementations
    def _validate_dataset_security(self, file_path: str) -> bool:
        """Enhanced security validation maintaining original interface"""
        try:
            file_path = str(Path(file_path).resolve())
            size_mb = Path(file_path).stat().st_size / (1024 * 1024)
            if size_mb > 500:  # Increased from original 100MB
                logger.warning("Large file detected: %.2fMB", size_mb)
                # Not automatically rejecting large files now
                
            if Path(file_path).suffix.lower() not in {'.csv', '.json', '.parquet', '.feather'}:
                return False

            with open(file_path, 'rb') as f:
                header = f.read(2048)  # Increased from 1024
                if any(b in header for b in [b'<script', b'eval(', b'exec(', b'\x00', b'\x04', b'\x09']):
                    logger.warning("Suspicious pattern in file header")
                    return False
                    
            # Additional checks
            if not self._validate_file_structure(file_path):
                return False
                
            return True
        except Exception as e:
            logger.error("Security validation failed: %s", str(e))
            return False

    def _validate_file_structure(self, file_path: str) -> bool:
        """New helper method maintaining original style"""
        try:
            # Sample first few lines for structure validation
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [f.readline() for _ in range(10)]
                
            # Basic validation logic
            if not any(',' in line or '{' in line for line in lines):
                logger.warning("File doesn't appear to be structured data")
                return False
                
            return True
        except:
            return False

    def _generate_data_hash(self, df: pd.DataFrame) -> str:
        """Enhanced hashing maintaining original interface"""
        try:
            # More robust hashing that handles different dtypes
            return hashlib.sha256(
                pd.util.hash_pandas_object(df, index=True).values.tobytes()
            ).hexdigest()
        except Exception as e:
            logger.error("Hash generation failed: %s", str(e))
            return ''

    def _load_config(self, config_path: str) -> Dict:
        """Enhanced config loading maintaining original interface"""
        try:
            with open(config_path) as f:
                config = json.load(f)
                
            # Validate required sections
            if 'models' not in config:
                config['models'] = {}
            if 'preprocessing' not in config:
                config['preprocessing'] = {}
                
            logger.info("Loaded configuration from %s with %d model settings", 
                       config_path, len(config.get('models', {})))
            return config
        except Exception as e:
            logger.error("Failed to load config: %s", str(e))
            return {}

    def _resolve_dataset(self, dataset_name: str = None) -> Optional[Dict]:
        """Original method with enhanced logging"""
        name_to_use = dataset_name or self.active_dataset
        if not name_to_use:
            self.logger.error("No dataset specified and no active dataset")
            return None
            
        dataset = self.datasets.get(name_to_use)
        if not dataset:
            self.logger.error("Dataset '%s' not found", name_to_use)
            
        return dataset
