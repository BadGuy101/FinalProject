import joblib
import numpy as np
import logging
from datetime import datetime
from typing import Dict, List
from sklearn.base import clone
from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier,
    HistGradientBoostingClassifier, IsolationForest,
    VotingClassifier
)
from sklearn.svm import OneClassSVM, SVC
from sklearn.neighbors import LocalOutlierFactor
from sklearn.linear_model import LogisticRegression
from imblearn.ensemble import BalancedRandomForestClassifier
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

logger = logging.getLogger("ML_Engine.ModelManager")

class ModelManager:
    """
    Enhanced model manager with support for multiple threat types and ensemble learning.
    """
    
    THREAT_SPECIFIC_MODELS = {
        'malware': ['random_forest', 'xgboost', 'hist_gbm'],
        'adware': ['random_forest', 'lgbm', 'svm'],
        'ransomware': ['isolation_forest', 'one_class_svm'],
        'malicious_website': ['random_forest', 'xgboost', 'logistic']
    }

    def __init__(self, data_manager):
        self.data_manager = data_manager
        self.models = self._initialize_models()
        self.model_performance = {}
        self.best_models = {}  # Track best model per threat type
        self.logger = logger

    def _initialize_models(self) -> Dict[str, object]:
        """Initialize models with optimized hyperparameters for different threats"""
        return {
            'random_forest': RandomForestClassifier(
                n_estimators=200, 
                class_weight='balanced', 
                max_depth=None,
                n_jobs=-1,
                random_state=42
            ),
            'hist_gbm': HistGradientBoostingClassifier(
                max_iter=200,
                learning_rate=0.1,
                max_depth=None,
                early_stopping=True,
                random_state=42
            ),
            'xgboost': XGBClassifier(
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
                random_state=42
            ),
            'isolation_forest': IsolationForest(
                n_estimators=200,
                contamination='auto',
                random_state=42,
                n_jobs=-1
            ),
            'one_class_svm': OneClassSVM(
                nu=0.05,
                kernel='rbf',
                gamma='scale'
            ),
            'svm': SVC(
                class_weight='balanced',
                probability=True,
                kernel='rbf',
                gamma='scale',
                random_state=42
            ),
            'logistic': LogisticRegression(
                class_weight='balanced',
                penalty='l2',
                solver='saga',
                max_iter=1000,
                n_jobs=-1,
                random_state=42
            ),
            'balanced_rf': BalancedRandomForestClassifier(
                n_estimators=100,
                sampling_strategy='auto',
                replacement=True,
                n_jobs=-1,
                random_state=42
            )
        }

    def train_model(self, model_name: str, dataset_name: str = None) -> bool:
        """Enhanced training with threat-specific handling"""
        try:
            dataset = self.data_manager._resolve_dataset(dataset_name)
            if not dataset:
                raise ValueError("Dataset not found")

            # Get appropriate data splits
            X = dataset.X_train if hasattr(dataset, 'X_train') else dataset.features
            y = dataset.y_train if hasattr(dataset, 'y_train') else dataset.labels
            
            if model_name not in self.models:
                raise ValueError(f"Model '{model_name}' not available")

            # Create pipeline with resampling if needed
            if model_name not in ['isolation_forest', 'one_class_svm']:
                pipeline = self._create_pipeline(model_name, dataset.threat_type)
            else:
                pipeline = clone(self.models[model_name])

            # Train model
            pipeline.fit(X, y)
            
            # Evaluate on test set if available
            if hasattr(dataset, 'X_test') and hasattr(dataset, 'y_test'):
                X_test = dataset.X_test
                y_test = dataset.y_test
                y_pred = pipeline.predict(X_test)
                y_proba = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, "predict_proba") else None
                
                metrics = {
                    'f1': f1_score(y_test, y_pred, average='weighted'),
                    'precision': precision_score(y_test, y_pred, average='weighted'),
                    'recall': recall_score(y_test, y_pred, average='weighted'),
                    'roc_auc': roc_auc_score(y_test, y_proba) if y_proba is not None else None,
                    'last_trained': datetime.now().isoformat(),
                    'dataset': dataset_name or self.data_manager.active_dataset,
                    'threat_type': dataset.threat_type
                }
            else:
                # Fallback to cross-validation
                cv_scores = cross_val_score(
                    pipeline, X, y,
                    cv=StratifiedKFold(5),
                    scoring='f1_weighted',
                    n_jobs=-1
                )
                metrics = {
                    'f1_mean': float(np.mean(cv_scores)),
                    'f1_std': float(np.std(cv_scores)),
                    'last_trained': datetime.now().isoformat(),
                    'dataset': dataset_name or self.data_manager.active_dataset,
                    'threat_type': dataset.threat_type
                }

            self.model_performance[model_name] = metrics
            self.models[model_name] = pipeline
            
            # Update best model for this threat type
            current_best = self.best_models.get(dataset.threat_type)
            if not current_best or metrics['f1'] > self.model_performance.get(current_best, {}).get('f1', 0):
                self.best_models[dataset.threat_type] = model_name

            self.logger.info(
                f"✅ Trained '{model_name}' on {dataset.threat_type} data | "
                f"F1: {metrics.get('f1', metrics.get('f1_mean', 0)):.4f}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Training failed for '{model_name}': {e}")
            return False

    def _create_pipeline(self, model_name: str, threat_type: str) -> ImbPipeline:
        """Create pipeline with appropriate resampling strategy"""
        base_model = clone(self.models[model_name])
        
        # Different resampling strategies per threat type
        if threat_type == 'ransomware':
            # Rare but severe - more aggressive oversampling
            return ImbPipeline([
                ('smote', SMOTE(sampling_strategy=0.5, random_state=42, k_neighbors=3)),
                ('model', base_model)
            ])
        elif threat_type == 'adware':
            # Common but less severe - balanced approach
            return ImbPipeline([
                ('smote', SMOTE(sampling_strategy=0.3, random_state=42)),
                ('undersample', RandomUnderSampler(sampling_strategy=0.5, random_state=42)),
                ('model', base_model)
            ])
        else:  # Generic pipeline
            return ImbPipeline([
                ('smote', SMOTE(sampling_strategy=0.2, random_state=42)),
                ('model', base_model)
            ])

    def train_all_models(self, dataset_name: str = None, parallel: bool = True) -> Dict:
        """Train all appropriate models for the dataset's threat type"""
        try:
            dataset = self.data_manager._resolve_dataset(dataset_name)
            if not dataset:
                raise ValueError("Dataset not found")
                
            # Get models specific to this threat type
            models_to_train = self.THREAT_SPECIFIC_MODELS.get(
                dataset.threat_type,
                ['random_forest', 'xgboost', 'lgbm']  # Default models
            )
            
            results = {}
            for model_name in models_to_train:
                results[model_name] = self.train_model(model_name, dataset_name)
                
            return results
        except Exception as e:
            self.logger.error(f"Batch training failed: {e}")
            return {}

    def save_model(self, model_name: str, file_path: str) -> bool:
        """Save model with additional metadata"""
        try:
            if model_name not in self.models:
                raise ValueError(f"Model '{model_name}' not found")
                
            metadata = {
                'model_name': model_name,
                'performance': self.model_performance.get(model_name, {}),
                'timestamp': datetime.now().isoformat()
            }
            
            joblib.dump({
                'model': self.models[model_name],
                'metadata': metadata
            }, file_path)
            
            self.logger.info(f"✅ Saved model '{model_name}' to {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Model save failed: {e}")
            return False

    def predict(self, features: np.ndarray, model_name: str = None, threat_type: str = None) -> int:
        """
        Enhanced prediction with threat-type specific model selection
        """
        try:
            # Select appropriate model
            if model_name:
                if model_name not in self.models:
                    raise ValueError(f"Model '{model_name}' not found")
                model = self.models[model_name]
            elif threat_type:
                model_name = self.best_models.get(threat_type)
                if not model_name:
                    raise ValueError(f"No best model for threat type '{threat_type}'")
                model = self.models[model_name]
            else:
                # Default to first best model found
                if not self.best_models:
                    raise ValueError("No models trained yet")
                model_name = next(iter(self.best_models.values()))
                model = self.models[model_name]

            # Reshape if single sample
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
                
            return model.predict(features)[0]
        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            return -1

    def predict_proba(self, features: np.ndarray, model_name: str = None) -> float:
        """Get prediction probability if available"""
        try:
            model_name = model_name or next(iter(self.best_models.values()))
            model = self.models[model_name]
            
            if not hasattr(model, 'predict_proba'):
                raise AttributeError(f"Model '{model_name}' doesn't support probability predictions")
                
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
                
            return model.predict_proba(features)[0, 1]  # Probability of positive class
        except Exception as e:
            self.logger.error(f"Probability prediction failed: {e}")
            return 0.5  # Neutral probability on error