import numpy as np
import pandas as pd
import logging
from enum import Enum
from typing import Tuple
from pathlib import Path
from dataclasses import dataclass
from typing import Any
from abc import ABC, abstractmethod
from sklearn.impute import SimpleImputer
from typing import Dict, List, Optional, Tuple, Union
from sklearn.ensemble import (
    RandomForestClassifier, IsolationForest, GradientBoostingClassifier,
    ExtraTreesClassifier, AdaBoostClassifier, VotingClassifier,
    StackingClassifier, HistGradientBoostingClassifier
)
from sklearn.tree import DecisionTreeClassifier, ExtraTreeClassifier
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.svm import SVC, OneClassSVM
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.linear_model import LogisticRegression, SGDClassifier, RidgeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier, LocalOutlierFactor, NearestCentroid
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_val_score,
    RandomizedSearchCV, GridSearchCV
)
from sklearn.preprocessing import (
    StandardScaler, MinMaxScaler, RobustScaler,
    PowerTransformer, QuantileTransformer
)
from sklearn.feature_selection import (
    SelectKBest, RFE, SelectFromModel, f_classif, mutual_info_classif
)
from sklearn.decomposition import PCA, KernelPCA, FastICA
from sklearn.cluster import KMeans, DBSCAN
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.base import clone
from imblearn.over_sampling import SMOTE, ADASYN
from imblearn.under_sampling import RandomUnderSampler
from imblearn.ensemble import BalancedRandomForestClassifier
import joblib
import json
import hashlib
from datetime import datetime
import warnings
from utils.audit_logger import AuditLogger
from utils.notifications import notify_user
from core.security_manager import SecurityManager





Audit_logger = AuditLogger()

# Suppress sklearn warnings
warnings.filterwarnings('ignore', category=UserWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ML_Engine")
class PreprocessingStrategy(Enum):
    DEFAULT = 'default'
    ROBUST = 'robust'
    MINIMAL = 'minimal'
    SECURITY = 'security'
@dataclass
class DatasetMetadata:
    name: str
    features: pd.DataFrame
    labels: pd.Series
    label_column: str
    file_path: str
    stats: Dict[str, Any]
    created_at: str
    version: float
    data_hash: str
    pipeline: Optional[Pipeline] = None
    processed_features: Optional[np.ndarray] = None
class BaseDataManager(ABC):
    """Abstract base class for data management"""
    
    @abstractmethod
    def load_dataset(self, file_path: str, label_column: str, 
                   dataset_name: str = None, security_scan: bool = True) -> bool:
        pass
        
    @abstractmethod
    def preprocess_dataset(self, dataset_name: str = None, 
                         strategy: PreprocessingStrategy = PreprocessingStrategy.DEFAULT) -> bool:
        pass
class DataManager(BaseDataManager):
    """Complete data management implementation with all original features"""
    
    def __init__(self, audit_logger: AuditLogger = None):
        self.datasets: Dict[str, DatasetMetadata] = {}
        self.active_dataset: Optional[str] = None
        self._preprocessing_cache: Dict[str, Any] = {}
        self.data_version = 1.0
        self.audit_logger = audit_logger or AuditLogger()
        self.logger = logging.getLogger("ML_Engine.DataManager")
        
        # Initialize all feature engineering components
        self.feature_engineering = {
            'scalers': {
                'standard': StandardScaler(),
                'minmax': MinMaxScaler(),
                'robust': RobustScaler(),
                'power': PowerTransformer(),
                'quantile': QuantileTransformer()
            },
            'selectors': {
                'kbest': SelectKBest(f_classif),
                'rfe': RFE(estimator=RandomForestClassifier()),
                'from_model': SelectFromModel(RandomForestClassifier())
            },
            'decomposition': {
                'pca': PCA(n_components=0.95),
                'kernel_pca': KernelPCA(n_components=10),
                'ica': FastICA(n_components=10)
            },
            'imputers': {  # ✅ Add this block
                'mean': SimpleImputer(strategy='mean'),
                'median': SimpleImputer(strategy='median'),
                'most_frequent': SimpleImputer(strategy='most_frequent')
            }
        }

    def _resolve_dataset(self, dataset_name: str = None) -> Optional[DatasetMetadata]:
        """Get dataset by name or active dataset"""
        name_to_use = dataset_name or self.active_dataset
        if not name_to_use:
            self.logger.error("No dataset specified and no active dataset")
            return None
            
        return self.datasets.get(name_to_use)
    def load_dataset(self, file_path: str, label_column: str, 
                   dataset_name: str = None, security_scan: bool = True) -> bool:
        """Complete dataset loading implementation"""
        try:
            # Security validation
            if security_scan and not self._validate_dataset_security(file_path):
                self.logger.error("Security validation failed for %s", file_path)
                self.audit_logger.log_event("DATA_LOAD_FAIL", f"Security check failed: {file_path}")
                return False
                
            # Determine dataset name
            if not dataset_name:
                dataset_name = Path(file_path).stem
                
            if dataset_name in self.datasets:
                raise ValueError(f"Dataset '{dataset_name}' already exists")
                
            # Load data based on file type
            df = self._load_data_file(file_path)
                
            # Validate dataset structure
            self._validate_dataset_structure(df, label_column)
                
            # Generate comprehensive stats
            stats = self._generate_dataset_stats(df, label_column)
            
            # Store dataset with metadata
            self.datasets[dataset_name] = DatasetMetadata(
                name=dataset_name,
                features=df.drop(columns=[label_column]),
                labels=df[label_column],
                label_column=label_column,
                file_path=file_path,
                stats=stats,
                created_at=datetime.now().isoformat(),
                version=self.data_version,
                data_hash=self._generate_data_hash(df)
            )
            
            # Set as active if first dataset
            if not self.active_dataset:
                self.active_dataset = dataset_name
                
            self.logger.info("Loaded dataset '%s' with %d samples", dataset_name, len(df))
            self.audit_logger.log_event("DATA_LOAD_SUCCESS", f"Loaded dataset: {dataset_name}")
            return True
            
        except Exception as e:
            self.logger.error("Dataset load failed: %s", str(e), exc_info=True)
            self.audit_logger.log_event("DATA_LOAD_ERROR", str(e))
            return False

    def preprocess_dataset(self, dataset_name: str = None, strategy: str = 'default') -> bool:
        """
        Apply feature engineering pipeline to dataset
        """
        try:
            dataset = self._resolve_dataset(dataset_name)
            if not dataset:
                self.logger.error("No dataset to preprocess.")
                return False

            # Define pipeline
            if strategy == 'robust':
                pipeline = Pipeline([
                    ('imputer', self.feature_engineering['imputers']['mean']),
                    ('scaler', self.feature_engineering['scalers']['robust']),
                    ('outlier_removal', self._create_outlier_remover()),
                    ('feature_selection', self.feature_engineering['selectors']['from_model']),
                    ('dim_reduction', self.feature_engineering['decomposition']['pca']),
                ])
            elif strategy == 'minimal':
                pipeline = Pipeline([
                    ('imputer', self.feature_engineering['imputers']['mean']),
                    ('scaler', self.feature_engineering['scalers']['minmax']),
                    ('feature_selection', self.feature_engineering['selectors']['kbest']),
                ])
            else:  # default
                pipeline = Pipeline([
                    ('imputer', self.feature_engineering['imputers']['mean']),
                    ('scaler', self.feature_engineering['scalers']['standard']),
                    ('feature_selection', self.feature_engineering['selectors']['rfe']),
                ])

            # Fit pipeline
            features = pipeline.fit_transform(dataset['features'], dataset['labels'])

            # 🔒 Fallback: if still NaNs, apply second-pass imputer
            if np.isnan(features).any():
                self.logger.warning("NaNs found after pipeline — applying final fallback imputer.")
                features = SimpleImputer(strategy='mean').fit_transform(features)

            # Store processed features
            dataset['processed_features'] = features
            dataset['pipeline'] = pipeline
            dataset['last_preprocessed'] = datetime.now().isoformat()

            self.logger.info("✅ Preprocessed dataset '%s': strategy=%s | shape=%s",
                            dataset_name or self.active_dataset, strategy, features.shape)
            return True

        except Exception as e:
            self.logger.error("❌ Preprocessing failed: %s", str(e), exc_info=True)
            return False


    def preprocess_dataset(self, dataset_name: str = None, strategy: str = 'default') -> bool:
        """Robust preprocessing with improved NaN handling"""
        try:
            # Map strategy string to PreprocessingStrategy enum
            strategy_map = {
                'default': PreprocessingStrategy.DEFAULT,
                'robust': PreprocessingStrategy.ROBUST,
                'minimal': PreprocessingStrategy.MINIMAL,
                'security': PreprocessingStrategy.SECURITY
            }
            
            # Get the dataset
            dataset = self.data_manager._resolve_dataset(dataset_name)
            if not dataset:
                self.logger.error("No dataset found to preprocess.")
                return False

            # Create preprocessing pipeline with robust NaN handling
            pipeline = self._create_preprocessing_pipeline(
                strategy_map.get(strategy, PreprocessingStrategy.DEFAULT)
            )

            # Check for NaN values before preprocessing
            if dataset.features.isna().any().any():
                self.logger.warning(f"Dataset contains {dataset.features.isna().sum().sum()} NaN values - applying imputation")

            # Apply pipeline with error handling
            try:
                features = pipeline.fit_transform(dataset.features, dataset.labels)
            except ValueError as e:
                self.logger.error(f"Initial preprocessing failed: {str(e)} - applying fallback imputation")
                # Apply simple imputer first if pipeline fails
                imputer = SimpleImputer(strategy='median')
                features_imputed = imputer.fit_transform(dataset.features)
                features = pipeline.fit_transform(features_imputed, dataset.labels)

            # Final check for remaining NaN values
            if np.isnan(features).any():
                self.logger.warning("NaN values still present after preprocessing - applying final cleanup")
                features = SimpleImputer(strategy='most_frequent').fit_transform(features)

            # Store processed results
            dataset.processed_features = features
            dataset.pipeline = pipeline

            self.logger.info(
                "✅ Successfully preprocessed dataset '%s' with strategy='%s' | Shape: %s",
                dataset_name or self.active_dataset,
                strategy,
                features.shape
            )
            return True

        except Exception as e:
            self.logger.error(f"❌ Preprocessing failed: {str(e)}", exc_info=True)
            return False

    def _validate_dataset_security(self, file_path: str) -> bool:
        """Perform security validation on dataset file"""
        try:
            # Normalize path to prevent path traversal
            file_path = str(Path(file_path).resolve())
            
            # Check file size (max 100MB)
            file_size = Path(file_path).stat().st_size / (1024 * 1024)
            if file_size > 100:
                logger.warning("Oversized dataset file: %.2fMB", file_size)
                return False
                
            # Check file extension
            valid_extensions = {'.csv', '.json', '.parquet'}
            if Path(file_path).suffix.lower() not in valid_extensions:
                logger.warning("Invalid file extension")
                return False
                
            # Check file headers for suspicious patterns
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                suspicious_patterns = [
                    b'<script', b'eval(', b'exec(', b'system('
                ]
                if any(pattern in header for pattern in suspicious_patterns):
                    logger.warning("Suspicious patterns detected in file header")
                    return False
                    
            return True

        except Exception as e:
            self.logger.error(f"Dataset load failed: {e}", exc_info=True)
            return False

    def _generate_dataset_stats(self, df: pd.DataFrame, label_column: str) -> Dict:
        """Generate comprehensive dataset statistics"""
        stats = {
            'samples': len(df),
            'features': len(df.columns) - 1,
            'missing_values': df.isna().sum().to_dict(),
            'class_distribution': df[label_column].value_counts().to_dict(),
            'dtypes': df.dtypes.astype(str).to_dict(),
            'numeric_stats': df.describe().to_dict() if df.select_dtypes(include=np.number).shape[1] > 0 else None,
            'categorical_stats': df.describe(include=['O']).to_dict() if df.select_dtypes(include='object').shape[1] > 0 else None
        }
        
        # Add correlation matrix if numeric features exist
        numeric_cols = df.select_dtypes(include=np.number).columns
        if len(numeric_cols) > 1:
            stats['correlation_matrix'] = df[numeric_cols].corr().to_dict()
            
        return stats

    def _generate_data_hash(self, df: pd.DataFrame) -> str:
        """Generate SHA256 hash of dataset contents"""
        # Convert the pandas hash to bytes and generate the final SHA256 hash
        hash_bytes = pd.util.hash_pandas_object(df).values.tobytes()
        return hashlib.sha256(hash_bytes).hexdigest()
    def _create_outlier_remover(self):
        """Create outlier removal transformer"""
        from sklearn.base import BaseEstimator, TransformerMixin
        
    
                
    def fit(self, X, y=None):
        if len(X.shape) == 1:
            X = X.reshape(-1, 1)
            self.median = np.median(X, axis=0)
            self.mad = np.median(np.abs(X - self.median), axis=0)
            return self
                
    def transform(self, X):
        if len(X.shape) == 1:
            X = X.reshape(-1, 1)
        z = 0.6745 * (X - self.median) / self.mad
        return X[(np.abs(z) < self.threshold).all(axis=1)]
        
        return OutlierRemover()
   
class ModelTrainer:
    """Complete model training implementation with all original features"""
    
    def __init__(self, data_manager: DataManager, audit_logger: AuditLogger = None):
        self.data_manager = data_manager
        self.audit_logger = audit_logger or AuditLogger()
        self.logger = logging.getLogger("ML_Engine.ModelTrainer")
        
        # Initialize all models and supporting structures
        self.models = self._initialize_models()
        self.ensembles = {}
        self.model_pipelines = {}
        self.model_performance = {}
        self.best_model = None
        self.model_hashes = {}
        self.experiment_history = []
        
        # Hyperparameter search spaces
        self.hyperparameter_spaces = {
            'random_forest': {
                'n_estimators': [100, 200, 300],
                'max_depth': [None, 10, 20, 30],
                'min_samples_split': [2, 5, 10]
            },
            # ... other model hyperparameter spaces
        }

    def _initialize_models(self) -> Dict[str, Any]:
        """Complete model initialization with all original models"""
        models = {
            # Tree-based
            'random_forest': RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42),
            'balanced_rf': BalancedRandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=150, random_state=42),
            'extra_trees': ExtraTreesClassifier(n_estimators=200, random_state=42),
            'hist_gbm': HistGradientBoostingClassifier(random_state=42),
            
            # Linear models
            'logistic': LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42),
            'ridge': RidgeClassifier(class_weight='balanced', random_state=42),
            'sgd': SGDClassifier(class_weight='balanced', random_state=42),
            
            # Neural networks
            'mlp': MLPClassifier(hidden_layer_sizes=(100,50), early_stopping=True, random_state=42),
            
            # Anomaly detection
            'isolation_forest': IsolationForest(n_estimators=150, contamination='auto', random_state=42),
            'one_class_svm': OneClassSVM(gamma='scale', nu=0.05),
            'lof': LocalOutlierFactor(novelty=True, n_neighbors=20),
            
            # Other classifiers
            'svm': SVC(class_weight='balanced', probability=True, random_state=42),
            'knn': KNeighborsClassifier(n_neighbors=5),
            'naive_bayes': GaussianNB(),
            'bernoulli_nb': BernoulliNB(),
            'nearest_centroid': NearestCentroid(),
            
            # Clustering models
            'kmeans': KMeans(n_clusters=5, random_state=42),
            'dbscan': DBSCAN(eps=0.5, min_samples=5)
        }
        
        # Add calibrated versions
        for name, model in list(models.items()):
            if name not in ['isolation_forest', 'one_class_svm', 'lof', 'kmeans', 'dbscan']:
                models[f'calibrated_{name}'] = CalibratedClassifierCV(model, cv=3)
        
        return models

    def train_model(self, model_name: str, dataset_name: str = None,
                   hyperparameters: Dict = None, cv_folds: int = 5) -> Dict:
        """Complete model training implementation"""
        try:
            # Validate 
            dataset = self.data_manager._resolve_dataset(dataset_name)
            if not dataset:
                raise ValueError("Invalid dataset")
                
            if model_name not in self.models:
                raise ValueError(f"Model '{model_name}' not found")
                
            # Get features and labels
            X = dataset.processed_features if dataset.processed_features is not None else dataset.features
            y = dataset.labels
            
            # Handle class imbalance
            X_res, y_res = self._handle_imbalance(X, y)
            
            # Clone base model
            model = clone(self.models[model_name])
            
            # Hyperparameter tuning if specified
            if hyperparameters:
                model = self._perform_hyperparameter_tuning(model, hyperparameters, cv_folds)
                best_params = model.best_params_
            else:
                best_params = None
                
            # Train final model
            model.fit(X_res, y_res)
            
            # If we did hyperparameter tuning, get the best estimator
            if hyperparameters:
                model = model.best_estimator_
                
            # Evaluate performance
            scores = self._evaluate_model(model, X, y, cv_folds)
            
            # Store trained model and performance
            self._store_model_results(model_name, model, scores, best_params, dataset_name)
            
            # Log success
            self.logger.info("Trained %s with F1=%.3f ± %.3f", 
                           model_name, np.mean(scores), np.std(scores))
            self.audit_logger.log_event("MODEL_TRAIN_SUCCESS", 
                                      f"Trained {model_name} with F1={np.mean(scores):.3f}")
            
            return {
                'status': 'success',
                'model': model_name,
                'performance': self.model_performance[model_name],
                'best_model': self.best_model == model_name
            }
            
        except Exception as e:
            self.logger.error("Model training failed: %s", str(e), exc_info=True)
            self.audit_logger.log_event("MODEL_TRAIN_FAILURE", str(e))
            return {
                'status': 'error',
                'error': str(e)
            }
    

    def _perform_hyperparameter_tuning(self, model, hyperparameters: Dict, cv_folds: int) -> Any:
        """
        Perform hyperparameter tuning using RandomizedSearchCV
        
        Args:
            model: The model to tune
            hyperparameters: Dictionary of hyperparameters and their ranges
            cv_folds: Number of cross-validation folds
            
        Returns:
            The trained RandomizedSearchCV object
        """
        try:
            self.logger.info(f"Starting hyperparameter tuning for {model.__class__.__name__}")
            
            search = RandomizedSearchCV(
                estimator=model,
                param_distributions=hyperparameters,
                n_iter=10,
                cv=cv_folds,
                scoring='f1_weighted',
                random_state=42,
                n_jobs=-1
            )
            
            return search
            
        except Exception as e:
            self.logger.error(f"Hyperparameter tuning failed: {str(e)}")
            raise RuntimeError(f"Hyperparameter tuning failed: {str(e)}")

    def _evaluate_model(self, model, X, y, cv_folds: int) -> np.ndarray:
        """
        Evaluate model performance using cross-validation
        
        Args:
            model: The trained model to evaluate
            X: Features
            y: Labels
            cv_folds: Number of cross-validation folds
            
        Returns:
            Array of cross-validation scores
        """
        try:
            self.logger.debug(f"Evaluating model {model.__class__.__name__} with {cv_folds}-fold CV")
            
            scores = cross_val_score(
                model,
                X,
                y,
                cv=StratifiedKFold(n_splits=cv_folds),
                scoring='f1_weighted',
                n_jobs=-1
            )
            
            return scores
            
        except Exception as e:
            self.logger.error(f"Model evaluation failed: {str(e)}")
            raise RuntimeError(f"Model evaluation failed: {str(e)}")

    def _store_model_results(self, model_name: str, model, scores: np.ndarray, 
                           best_params: Optional[Dict], dataset_name: str) -> None:
        """
        Store trained model and its performance metrics
        
        Args:
            model_name: Name of the model
            model: The trained model object
            scores: Cross-validation scores
            best_params: Best parameters from tuning (if any)
            dataset_name: Name of dataset used for training
        """
        model_hash = self._generate_model_hash(model)
        
        self.model_performance[model_name] = {
            'f1_mean': float(np.mean(scores)),
            'f1_std': float(np.std(scores)),
            'best_params': best_params,
            'last_trained': datetime.now().isoformat(),
            'model_hash': model_hash,
            'dataset': dataset_name or self.data_manager.active_dataset,
            'feature_importances': self._get_feature_importances(model) if hasattr(model, 'feature_importances_') else None
        }
        
        # Update model registry
        self.models[model_name] = model
        self.model_hashes[model_name] = model_hash
        
        # Update best model if better performance
        current_best_score = self.model_performance.get(self.best_model, {}).get('f1_mean', 0)
        if np.mean(scores) > current_best_score:
            self.best_model = model_name
            self.logger.info(f"New best model: {model_name} with F1={np.mean(scores):.3f}")

    def _handle_imbalance(self, X, y) -> Tuple[np.ndarray, np.ndarray]:
        """
        Handle class imbalance using adaptive SMOTE and RandomUnderSampler with improved safety checks.
        
        Args:
            X: Input features (numpy array or pandas DataFrame)
            y: Target labels (numpy array or pandas Series)
            
        Returns:
            Tuple of (resampled_features, resampled_labels)
            
        Raises:
            ValueError: If input data is invalid
        """
        try:
            # Input validation
            if X.shape[0] != y.shape[0]:
                raise ValueError("X and y must have the same number of samples")
                
            if X.shape[0] == 0:
                raise ValueError("Empty dataset provided")

            # Convert categorical labels to numeric if needed
            if hasattr(y, "dtype") and y.dtype.kind in {'U', 'O'}:
                y_encoded, _ = pd.factorize(y)
            else:
                y_encoded = y

            # Calculate class distribution
            class_counts = np.bincount(y_encoded)
            valid_classes = class_counts[class_counts > 0]  # Filter out empty classes
            
            if len(valid_classes) < 2:
                self.logger.warning("Only one class found - skipping resampling")
                return X, y

            imbalance_ratio = max(valid_classes) / min(valid_classes)
            
            # Only resample if significant imbalance exists
            if imbalance_ratio > 5:  # Customizable threshold
                self.logger.info(f"Resampling data (imbalance ratio: {imbalance_ratio:.1f}:1)")
                
                # Adaptive SMOTE configuration
                min_samples = min(valid_classes)
                k_neighbors = min(5, min_samples - 1)  # Ensure k_neighbors <= min_samples - 1
                
                # SMOTE for oversampling minority class
                smote = SMOTE(
                    sampling_strategy=0.5,  # Oversample minority to 50% of majority
                    random_state=42,
                    k_neighbors=k_neighbors,
                    n_jobs=-1  # Use all available cores
                )
                
                # Random undersampling of majority class
                under = RandomUnderSampler(
                    sampling_strategy=0.8,  # Undersample majority to 80% of original
                    random_state=42
                )
                
                try:
                    # First oversample, then undersample
                    X_res, y_res = smote.fit_resample(X, y)
                    X_res, y_res = under.fit_resample(X_res, y_res)
                    
                    # Validate output shapes
                    if X_res.shape[0] != y_res.shape[0]:
                        raise ValueError("Resampling produced inconsistent shapes")
                        
                    self.logger.debug(f"Resampling complete. New shape: {X_res.shape}")
                    return X_res, y_res
                    
                except ValueError as ve:
                    self.logger.error(f"Resampling failed: {str(ve)} - using original data")
                    return X, y

            return X, y
            
        except Exception as e:
            self.logger.error(f"Imbalance handling failed: {str(e)} - using original data", 
                            exc_info=True)
            return X, y
    
    def _generate_model_hash(self, model) -> str:
        """
        Generate SHA256 hash of model parameters and configuration
        
        Args:
            model: The model to hash
            
        Returns:
            SHA256 hash string
        """
        try:
            # Include both parameters and configuration in hash
            hash_data = {
                'params': model.get_params(),
                'config': {
                    'model_type': str(type(model)),
                    'features': getattr(model, 'feature_names_in_', None)
                }
            }
            return hashlib.sha256(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to generate model hash: {str(e)}")
            return "unknown_hash"

    def create_ensemble(self, model_names: List[str], ensemble_name: str,
                       method: str = 'voting') -> bool:
        """
        Create an ensemble of models
        
        Args:
            model_names: List of model names to include
            ensemble_name: Name for the new ensemble
            method: Either 'voting' or 'stacking'
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.logger.info(f"Creating {method} ensemble '{ensemble_name}'")
            
            # Validate input models
            valid_models = []
            for name in model_names:
                if name in self.models and name in self.model_performance:
                    valid_models.append((name, self.models[name]))
                else:
                    self.logger.warning(f"Skipping invalid model: {name}")

            if len(valid_models) < 2:
                raise ValueError("Need at least 2 valid models for ensemble")

            # Create appropriate ensemble type
            if method == 'stacking':
                final_estimator = LogisticRegression(
                    class_weight='balanced',
                    max_iter=1000,
                    random_state=42
                )
                ensemble = StackingClassifier(
                    estimators=valid_models,
                    final_estimator=final_estimator,
                    cv=5,
                    n_jobs=-1
                )
            else:  # voting
                ensemble = VotingClassifier(
                    estimators=valid_models,
                    voting='soft',
                    n_jobs=-1
                )

            # Store ensemble and its configuration
            self.ensembles[ensemble_name] = ensemble
            self.model_performance[ensemble_name] = {
                'ensemble_type': method,
                'constituent_models': model_names,
                'created_at': datetime.now().isoformat()
            }
            
            self.logger.info(f"Created {method} ensemble '{ensemble_name}' with {len(valid_models)} models")
            return True
            
        except Exception as e:
            self.logger.error(f"Ensemble creation failed: {str(e)}")
            return False

    def save_model(self, model_name: str, file_path: str) -> bool:
        """
        Save trained model to disk with verification
        
        Args:
            model_name: Name of model to save
            file_path: Path to save the model
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if model_name not in self.models:
                raise ValueError(f"Model '{model_name}' not found")

            # Create directory if needed
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Save model
            joblib.dump(self.models[model_name], file_path)
            
            # Verify saved model
            loaded_model = joblib.load(file_path)
            if self._generate_model_hash(loaded_model) != self.model_hashes.get(model_name):
                raise ValueError("Model hash mismatch after saving")
                
            self.logger.info(f"Saved model '{model_name}' to {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save model '{model_name}': {str(e)}")
            return False

    def load_model(self, file_path: str, model_name: str = None) -> bool:
        """
        Load trained model from disk with verification
        
        Args:
            file_path: Path to model file
            model_name: Optional name for the model
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not Path(file_path).exists():
                raise FileNotFoundError(f"Model file not found: {file_path}")

            model = joblib.load(file_path)
            model_name = model_name or Path(file_path).stem

            if not hasattr(model, 'predict'):
                raise ValueError("Loaded object is not a valid scikit-learn model")

            # Verify model can predict
            try:
                dummy_input = np.zeros((1, model.n_features_in_)) if hasattr(model, 'n_features_in_') else np.zeros((1, 1))
                model.predict(dummy_input)
            except Exception as e:
                raise ValueError(f"Model prediction verification failed: {str(e)}")

            # Store model
            self.models[model_name] = model
            self.model_hashes[model_name] = self._generate_model_hash(model)
            
            self.logger.info(f"Loaded model '{model_name}' from {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load model from {file_path}: {str(e)}")
            return False

    def explain_prediction(self, features, model_name: str = None) -> Dict:
        """
        Generate explanation for a model prediction
        
        Args:
            features: Input features to explain
            model_name: Name of model to use (best model if None)
            
        Returns:
            Dictionary with explanation results
        """
        try:
            model_to_use = model_name or self.best_model
            if not model_to_use:
                raise ValueError("No trained model available")

            model = self.models[model_to_use]
            
            # Convert input to numpy array if needed
            if not isinstance(features, np.ndarray):
                features = np.array(features)
            if len(features.shape) == 1:
                features = features.reshape(1, -1)

            # Basic feature importance for tree models
            explanation = {
                'model': model_to_use,
                'timestamp': datetime.now().isoformat(),
                'feature_importance': {},
                'prediction': model.predict(features)[0]
            }

            if hasattr(model, 'feature_importances_'):
                if hasattr(model, 'feature_names_in_'):
                    feature_names = model.feature_names_in_
                else:
                    feature_names = [f'feature_{i}' for i in range(len(model.feature_importances_))]
                
                explanation['feature_importance'] = dict(zip(
                    feature_names,
                    model.feature_importances_
                ))

            # TODO: Add SHAP/LIME integration here
            self.logger.debug(f"Generated explanation for {model_to_use}")
            return explanation
            
        except Exception as e:
            self.logger.error(f"Explanation failed: {str(e)}")
            return {
                'error': str(e),
                'status': 'error'
            }

    def get_performance_report(self) -> Dict:
        """
        Generate comprehensive performance report for all models
        
        Returns:
            Dictionary containing performance metrics for all models
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'best_model': self.best_model,
            'models': {},
            'ensembles': {},
            'active_dataset': self.data_manager.active_dataset,
            'dataset_stats': {}
        }

        # Add model performances
        for name, metrics in self.model_performance.items():
            if name in self.models:
                report['models'][name] = metrics
            elif name in self.ensembles:
                report['ensembles'][name] = metrics

        # Add dataset statistics
        for name, dataset in self.data_manager.datasets.items():
            report['dataset_stats'][name] = dataset.stats

        return report

    def _get_feature_importances(self, model) -> Optional[Dict]:
        """Helper method to extract feature importances if available"""
        if hasattr(model, 'feature_importances_'):
            if hasattr(model, 'feature_names_in_'):
                return dict(zip(model.feature_names_in_, model.feature_importances_))
            return dict(enumerate(model.feature_importances_))
        return None
class ThreatDetector:
    """Complete threat detection implementation with all original features"""
    
    def __init__(self, model_trainer: ModelTrainer, security_manager: SecurityManager,
                audit_logger: AuditLogger = None):
        self.model_trainer = model_trainer
        self.security_manager = security_manager
        self.audit_logger = audit_logger or AuditLogger()
        self.logger = logging.getLogger("ML_Engine.ThreatDetector")
        self.file_scanner = FileScanner()
        self.quarantine_manager = QuarantineManager()

    def analyze_process(self, pid: int) -> Dict:
        """Complete process analysis implementation"""
        try:
            if not psutil.pid_exists(pid):
                self.logger.warning(f"Process with PID {pid} does not exist")
                return {'status': 'error', 'message': 'Process not found'}
                
            self.logger.info(f"Analyzing process PID {pid}...")
            
            if self.is_suspicious(pid):
                self.logger.warning(f"Suspicious activity detected in PID {pid}")
                self.security_manager.protect_process(pid)
                self.audit_logger.log_event("THREAT_DETECTED", f"Suspicious process {pid}")
                return {'status': 'protected', 'pid': pid}
            else:
                self.logger.info(f"Process PID {pid} is safe")
                return {'status': 'clean', 'pid': pid}

        except Exception as e:
            self.logger.error(f"Error analyzing PID {pid}: {e}")
            self.audit_logger.log_event("PROCESS_ANALYSIS_ERROR", str(e))
            return {'status': 'error', 'error': str(e)}

    def is_suspicious(self, pid: int) -> bool:
        """Complete suspicious process detection"""
        try:
            proc = psutil.Process(pid)
            features = self._extract_process_features(proc)
            
            # Get predictions from all anomaly detection models
            anomaly_models = ['isolation_forest', 'one_class_svm', 'lof']
            predictions = []
            
            for model_name in anomaly_models:
                if model_name in self.model_trainer.models:
                    model = self.model_trainer.models[model_name]
                    try:
                        pred = model.predict([features])
                        # Different models return different anomaly indicators
                        if model_name == 'isolation_forest':
                            predictions.append(pred[0] == -1)
                        elif model_name == 'one_class_svm':
                            predictions.append(pred[0] == -1)
                        elif model_name == 'lof':
                            predictions.append(pred[0] == -1)
                    except Exception as e:
                        self.logger.warning(f"Prediction failed with {model_name}: {e}")
                        
            return any(predictions)

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Access issue for PID {pid}: {e}")
            return False

    def scan_file_and_alert(self, file_path: str) -> Dict:
        """Complete file scanning implementation"""
        try:
            result = self.file_scanner.scan_file(file_path)
            if result["verdict"] != "benign":
                notify_user("🚨 Threat Detected", f"{result['verdict'].upper()} in file: {file_path}")
                self.quarantine_manager.quarantine_file(file_path)
                self.audit_logger.log_event("FILE_THREAT_DETECTED", 
                                          f"{result['verdict']} in {file_path}")
                return {'status': 'quarantined', 'file': file_path, 'verdict': result['verdict']}
            return {'status': 'clean', 'file': file_path}
        except Exception as e:
            self.logger.error(f"File scan failed for {file_path}: {e}")
            return {'status': 'error', 'error': str(e)}

    def _extract_process_features(self, proc) -> List[float]:
        """Complete feature extraction for process analysis"""
        try:
            with proc.oneshot():
                return [
                    proc.cpu_percent(interval=0.1),
                    proc.memory_percent(),
                    proc.num_threads(),
                    len(proc.connections()),
                    len(proc.open_files()),
                    proc.io_counters().read_count if proc.io_counters() else 0,
                    proc.io_counters().write_count if proc.io_counters() else 0,
                    proc.nice(),
                    len(proc.children())
                ]
        except Exception as e:
            self.logger.warning(f"Feature extraction failed: {e}")
            return []
          
class AdvancedMLEngine:
    """Enterprise-grade ML Engine for security analytics with advanced features"""
    def __init__(self, config_path: str = None, model_path: str = None):
        self.logger = logging.getLogger("ML_Engine")
        # Model registry
        self.security_manager = SecurityManager()
        self.models = self._initialize_models()
        self.ensembles = {}
        self.model_pipelines = {}

        # Data management
        self.datasets = {}
        self.active_dataset = None
        self.data_version = 1.0

        # Feature engineering
        self.feature_engineering = {
            'scalers': {
                'standard': StandardScaler(),
                'minmax': MinMaxScaler(),
                'robust': RobustScaler(),
                'power': PowerTransformer(),
                'quantile': QuantileTransformer()
            },
            'selectors': {
                'kbest': SelectKBest(f_classif),
                'rfe': RFE(estimator=RandomForestClassifier()),
                'from_model': SelectFromModel(RandomForestClassifier())
            },
            'decomposition': {
                'pca': PCA(n_components=0.95),
                'kernel_pca': KernelPCA(n_components=10),
                'ica': FastICA(n_components=10)
            },
            'imputers': {  # ✅ Add this block
                'mean': SimpleImputer(strategy='mean'),
                'median': SimpleImputer(strategy='median'),
                'most_frequent': SimpleImputer(strategy='most_frequent')
            }
        }

        # Performance tracking
        self.model_performance = {}
        self.experiment_history = []
        self.best_model = None

        # Security features
        self.model_hashes = {}
        self.data_hashes = {}

        # Store model path if provided
        self.model_path = model_path

        # Load configuration if provided
        self.config = self._load_config(config_path) if config_path else {}

        logger.info("ML Engine initialized with %d base models", len(self.models))
    def _resolve_dataset(self, dataset_name: str = None) -> Optional[Dict]:
        """Get dataset by name or fallback to active dataset"""
        name_to_use = dataset_name or self.active_dataset
        if not name_to_use:
            self.logger.error("No dataset specified and no active dataset")
            return None

        if name_to_use not in self.datasets:
            self.logger.error("Dataset '%s' not found", name_to_use)
            return None

        return self.datasets[name_to_use]

    def analyze_process(self, pid: int):
        """Analyzes a process and applies protection if found suspicious."""
        try:
            if not psutil.pid_exists(pid):
                self.logger.warning(f"Process with PID {pid} does not exist.")
                return
            
            self.logger.info(f"Analyzing process PID {pid}...")

            if self.is_suspicious(pid):
                self.logger.warning(f"Suspicious activity detected in PID {pid}. Taking action.")
                self.security_manager.protect_process(pid)
            else:
                self.logger.info(f"Process PID {pid} is safe.")

        except Exception as e:
            self.logger.error(f"Error during analysis of PID {pid}: {e}")

    def is_suspicious(self, pid: int) -> bool:
        """
        Simulated ML logic to flag a process as suspicious.
        Replace this with actual ML model inference in the future.
        """
        try:
            proc = psutil.Process(pid)
            cpu_usage = proc.cpu_percent(interval=0.1)
            mem_usage = proc.memory_percent()

            self.logger.debug(f"PID {pid} → CPU: {cpu_usage}%, MEM: {mem_usage}%")

            # Simulated threat logic (temporary placeholder)
            if cpu_usage > 80.0 or mem_usage > 70.0:
                return True

            # TODO: Inject real ML prediction here using extracted features
            return False

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Access issue for PID {pid}: {e}")
            return False




    def scan_file_and_alert(self, file_path):
        result = self.file_scanner.scan_file(file_path)
        if result["verdict"] != "benign":
            notify_user("🚨 Threat Detected", f"{result['verdict'].upper()} in file: {file_path}")
            self.quarantine_manager.quarantine_file(file_path)


    
    def _initialize_models(self) -> Dict:
        """Initialize all ML models with default parameters"""
        models = {
            # Tree-based
            'random_forest': RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42),
            'balanced_rf': BalancedRandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=150, random_state=42),
            'extra_trees': ExtraTreesClassifier(n_estimators=200, random_state=42),
            'hist_gbm': HistGradientBoostingClassifier(random_state=42),
            
            # Linear models
            'logistic': LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42),
            'ridge': RidgeClassifier(class_weight='balanced', random_state=42),
            'sgd': SGDClassifier(class_weight='balanced', random_state=42),
            
            # Neural networks
            'mlp': MLPClassifier(hidden_layer_sizes=(100,50), early_stopping=True, random_state=42),
            
            # Anomaly detection
            'isolation_forest': IsolationForest(n_estimators=150, contamination='auto', random_state=42),
            'one_class_svm': OneClassSVM(gamma='scale', nu=0.05),
            'lof': LocalOutlierFactor(novelty=True, n_neighbors=20),
            
            # Other classifiers
            'svm': SVC(class_weight='balanced', probability=True, random_state=42),
            'knn': KNeighborsClassifier(n_neighbors=5),
            'naive_bayes': GaussianNB(),
            'bernoulli_nb': BernoulliNB(),
            'nearest_centroid': NearestCentroid()
        }
        
        # Add calibrated versions
        for name, model in list(models.items()):
            if name not in ['isolation_forest', 'one_class_svm', 'lof']:
                models[f'calibrated_{name}'] = CalibratedClassifierCV(model, cv=3)
        
        return models

    def _load_config(self, config_path: str) -> Dict:
        """Load engine configuration from JSON file"""
        try:
            with open(config_path) as f:
                config = json.load(f)
            
            # Validate config structure
            required_sections = ['models', 'feature_engineering']
            if not all(section in config for section in required_sections):
                raise ValueError("Invalid config structure")
                
            logger.info("Loaded configuration from %s", config_path)
            return config
            
        except Exception as e:
            logger.error("Config load failed: %s", str(e))
            return {}

    # --------------------------
    # DATA MANAGEMENT METHODS
    # --------------------------
    
    def load_dataset(self, file_path: str, label_column: str, dataset_name: str = None, 
                   security_scan: bool = True) -> bool:
        """
        Advanced dataset loading with security checks and automatic preprocessing
        
        Args:
            file_path: Path to dataset file (CSV, JSON, Parquet)
            label_column: Name of target/label column
            dataset_name: Optional identifier for the dataset
            security_scan: Whether to perform security validation
            
        Returns:
            bool: True if successful
        """
        try:
            # Security validation
            if security_scan and not self._validate_dataset_security(file_path):
                logger.error("Security validation failed for %s", file_path)
                return False
                
            # Determine dataset name
            if not dataset_name:
                dataset_name = Path(file_path).stem
                
            if dataset_name in self.datasets:
                raise ValueError(f"Dataset '{dataset_name}' already exists")
                
            # Load data based on file type
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext == '.csv':
                df = pd.read_csv(file_path, engine='python')
            elif file_ext == '.json':
                df = pd.read_json(file_path)
            elif file_ext == '.parquet':
                df = pd.read_parquet(file_path)
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")
                
            # Validate dataset structure
            if label_column not in df.columns:
                raise ValueError(f"Label column '{label_column}' not found")
                
            if len(df) < 10:
                raise ValueError("Insufficient samples (minimum 10 required)")
                
            # Store dataset with metadata
            self.datasets[dataset_name] = {
                'raw_data': df,
                'features': df.drop(columns=[label_column]),
                'labels': df[label_column],
                'label_column': label_column,
                'file_path': file_path,
                'stats': self._generate_dataset_stats(df, label_column),
                'created_at': datetime.now().isoformat(),
                'version': self.data_version,
                'hash': self._generate_data_hash(df)
            }
            
            # Set as active if first dataset
            if not self.active_dataset:
                self.active_dataset = dataset_name
                
            logger.info("Loaded dataset '%s' with %d samples", dataset_name, len(df))
            return True
            
        except Exception as e:
            logger.error("Dataset load failed: %s", str(e), exc_info=True)
            return False

    def _validate_dataset_security(self, file_path: str) -> bool:
        """Perform security validation on dataset file"""
        try:
            # Normalize path to prevent path traversal
            file_path = str(Path(file_path).resolve())
            
            # Check file size (max 100MB)
            file_size = Path(file_path).stat().st_size / (1024 * 1024)
            if file_size > 100:
                logger.warning("Oversized dataset file: %.2fMB", file_size)
                return False
                
            # Check file extension
            valid_extensions = {'.csv', '.json', '.parquet'}
            if Path(file_path).suffix.lower() not in valid_extensions:
                logger.warning("Invalid file extension")
                return False
                
            # Check file headers for suspicious patterns
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                suspicious_patterns = [
                    b'<script', b'eval(', b'exec(', b'system('
                ]
                if any(pattern in header for pattern in suspicious_patterns):
                    logger.warning("Suspicious patterns detected in file header")
                    return False
                    
            return True

        except Exception as e:
            self.logger.error(f"Dataset load failed: {e}", exc_info=True)
            return False

    def _generate_dataset_stats(self, df: pd.DataFrame, label_column: str) -> Dict:
        """Generate comprehensive dataset statistics"""
        stats = {
            'samples': len(df),
            'features': len(df.columns) - 1,
            'missing_values': df.isna().sum().to_dict(),
            'class_distribution': df[label_column].value_counts().to_dict(),
            'dtypes': df.dtypes.astype(str).to_dict(),
            'numeric_stats': df.describe().to_dict() if df.select_dtypes(include=np.number).shape[1] > 0 else None,
            'categorical_stats': df.describe(include=['O']).to_dict() if df.select_dtypes(include='object').shape[1] > 0 else None
        }
        
        # Add correlation matrix if numeric features exist
        numeric_cols = df.select_dtypes(include=np.number).columns
        if len(numeric_cols) > 1:
            stats['correlation_matrix'] = df[numeric_cols].corr().to_dict()
            
        return stats

    def _generate_data_hash(self, df: pd.DataFrame) -> str:
        """Generate SHA256 hash of dataset contents"""
        # Convert the pandas hash to bytes and generate the final SHA256 hash
        hash_bytes = pd.util.hash_pandas_object(df).values.tobytes()
        return hashlib.sha256(hash_bytes).hexdigest()

    # --------------------------
    # FEATURE ENGINEERING
    # --------------------------
    
    def preprocess_dataset(self, dataset_name: str = None, strategy: str = 'default') -> bool:
        """Robust preprocessing with improved NaN handling"""
        try:
            # Map strategy string to PreprocessingStrategy enum
            strategy_map = {
                'default': PreprocessingStrategy.DEFAULT,
                'robust': PreprocessingStrategy.ROBUST,
                'minimal': PreprocessingStrategy.MINIMAL,
                'security': PreprocessingStrategy.SECURITY
            }
            
            # Get the dataset
            dataset = self.data_manager._resolve_dataset(dataset_name)
            if not dataset:
                self.logger.error("No dataset found to preprocess.")
                return False

            # Create preprocessing pipeline with robust NaN handling
            pipeline = self._create_preprocessing_pipeline(
                strategy_map.get(strategy, PreprocessingStrategy.DEFAULT)
            )

            # Check for NaN values before preprocessing
            if dataset.features.isna().any().any():
                self.logger.warning(f"Dataset contains {dataset.features.isna().sum().sum()} NaN values - applying imputation")

            # Apply pipeline with error handling
            try:
                features = pipeline.fit_transform(dataset.features, dataset.labels)
            except ValueError as e:
                self.logger.error(f"Initial preprocessing failed: {str(e)} - applying fallback imputation")
                # Apply simple imputer first if pipeline fails
                imputer = SimpleImputer(strategy='median')
                features_imputed = imputer.fit_transform(dataset.features)
                features = pipeline.fit_transform(features_imputed, dataset.labels)

            # Final check for remaining NaN values
            if np.isnan(features).any():
                self.logger.warning("NaN values still present after preprocessing - applying final cleanup")
                features = SimpleImputer(strategy='most_frequent').fit_transform(features)

            # Store processed results
            dataset.processed_features = features
            dataset.pipeline = pipeline

            self.logger.info(
                "✅ Successfully preprocessed dataset '%s' with strategy='%s' | Shape: %s",
                dataset_name or self.active_dataset,
                strategy,
                features.shape
            )
            return True

        except Exception as e:
            self.logger.error(f"❌ Preprocessing failed: {str(e)}", exc_info=True)
            return False

class OutlierRemover(BaseEstimator, TransformerMixin):
    def __init__(self, threshold=3):
        self.threshold = threshold

    def fit(self, X, y=None):
        X = np.asarray(X)
        if len(X.shape) == 1:
            X = X.reshape(-1, 1)
        self.median = np.median(X, axis=0)
        self.mad = np.median(np.abs(X - self.median), axis=0)
        self.mad = np.where(self.mad == 0, 1e-6, self.mad)
        return self

    def transform(self, X):
        X = np.asarray(X)
        if len(X.shape) == 1:
            X = X.reshape(-1, 1)
        z = 0.6745 * (X - self.median) / self.mad
        mask = (np.abs(z) < self.threshold).all(axis=1)
        return X[mask]



    # --------------------------
    # MODEL TRAINING
    # --------------------------
    
    def train_model(self, model_name: str, dataset_name: str = None,
                   hyperparameters: Dict = None, cv_folds: int = 5) -> Dict:
        """
        Train a specific model with optional hyperparameter tuning
        
        Args:
            model_name: Name of model to train
            dataset_name: Dataset to use (active if None)
            hyperparameters: Dict of hyperparameters to tune
            cv_folds: Number of cross-validation folds
            
        Returns:
            Dict: Training results
        """
        try:
            dataset = self._resolve_dataset(dataset_name)
            if not dataset:
                raise ValueError("Invalid dataset")
                
            if model_name not in self.models:
                raise ValueError(f"Model '{model_name}' not found")
                
            # Get features and labels
            X = dataset['processed_features'] if 'processed_features' in dataset else dataset['features']
            y = dataset['labels']
            
            # Handle class imbalance
            X_res, y_res = self._handle_imbalance(X, y)
            
            # Clone base model
            model = clone(self.models[model_name])
            
            # Hyperparameter tuning if specified
            if hyperparameters:
                model = RandomizedSearchCV(
                    model,
                    hyperparameters,
                    n_iter=10,
                    cv=cv_folds,
                    scoring='f1_weighted',
                    random_state=42
                )
            
            # Train model
            model.fit(X_res, y_res)
            
            # Store best model if tuned
            if hyperparameters:
                model = model.best_estimator_
                best_params = model.best_params_
            else:
                best_params = None
                
            # Evaluate performance
            scores = cross_val_score(
                model, X, y, 
                cv=cv_folds,
                scoring='f1_weighted'
            )
            
            # Store trained model
            model_hash = self._generate_model_hash(model)
            self.model_hashes[model_name] = model_hash
            
            # Update performance tracking
            self.model_performance[model_name] = {
                'f1_mean': np.mean(scores),
                'f1_std': np.std(scores),
                'best_params': best_params,
                'last_trained': datetime.now().isoformat(),
                'model_hash': model_hash,
                'dataset': dataset_name or self.active_dataset
            }
            
            # Update best model if better performance
            current_best = self.model_performance.get(
                self.best_model, {}).get('f1_mean', 0)
            if np.mean(scores) > current_best:
                self.best_model = model_name
                
            logger.info("Trained %s with F1=%.3f ± %.3f", 
                       model_name, np.mean(scores), np.std(scores))
            
            return {
                'status': 'success',
                'model': model_name,
                'performance': self.model_performance[model_name],
                'best_model': self.best_model == model_name
            }
            
        except Exception as e:
            logger.error("Model training failed: %s", str(e), exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }

    def _handle_imbalance(self, X, y):
        """Apply SMOTE oversampling and random undersampling"""
        try:
            # Convert categorical labels to numeric if needed
            if hasattr(y, "dtype") and y.dtype.kind in {'U', 'O'}:
                y_encoded, uniques = pd.factorize(y)
            else:
                y_encoded = y

            # Only resample if significant imbalance exists
            class_counts = np.bincount(y_encoded)
            if len(class_counts) < 2:
                logging.warning("Only one class found in dataset. Skipping resampling.")
                return X, y  # Can't resample with only one class

            imbalance_ratio = max(class_counts) / min(class_counts)

            if imbalance_ratio > 5:  # Significant imbalance
                smote = SMOTE(sampling_strategy=0.5, random_state=42)
                under = RandomUnderSampler(sampling_strategy=0.8, random_state=42)

                X_res, y_res = smote.fit_resample(X, y)
                X_res, y_res = under.fit_resample(X_res, y_res)
                return X_res, y_res

            return X, y

        except Exception as e:
            logging.warning("Imbalance handling failed: %s", str(e))
            return X, y
    
    def _generate_model_hash(self, model) -> str:
        """Generate SHA256 hash of model parameters"""
        return hashlib.sha256(str(model.get_params()).encode()).hexdigest()

    # --------------------------
    # PREDICTION METHODS
    # --------------------------
    
    def predict(self, features, model_name: str = None, 
               return_proba: bool = False, threshold: float = 0.5) -> Dict:
        """
        Make predictions using specified or best model
        
        Args:
            features: Input features for prediction
            model_name: Model to use (best if None)
            return_proba: Whether to return probabilities
            threshold: Classification threshold
            
        Returns:
            Dict: Prediction results
        """
        try:
            model_to_use = model_name or self.best_model
            if not model_to_use:
                raise ValueError("No trained model available")
                
            if model_to_use not in self.model_performance:
                raise ValueError(f"Model '{model_to_use}' not trained")
                
            # Get model (in production would load from storage)
            model = self.models[model_to_use]
            
            # Convert input to numpy if needed
            if not isinstance(features, np.ndarray):
                features = np.array(features)
                
            # Ensure correct shape
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
                
            # Make prediction
            if return_proba and hasattr(model, 'predict_proba'):
                proba = model.predict_proba(features)
                prediction = (proba[:, 1] >= threshold).astype(int)
                return {
                    'prediction': prediction,
                    'probability': proba,
                    'model': model_to_use,
                    'threshold': threshold
                }
            else:
                prediction = model.predict(features)
                return {
                    'prediction': prediction,
                    'model': model_to_use
                }
                
        except Exception as e:
            logger.error("Prediction failed: %s", str(e), exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }

    # --------------------------
    # MODEL MANAGEMENT
    # --------------------------
    
    def save_model(self, model_name: str, file_path: str) -> bool:
        """Save trained model to disk"""
        try:
            if model_name not in self.models:
                raise ValueError(f"Model '{model_name}' not found")
                
            joblib.dump(self.models[model_name], file_path)
            
            # Verify saved model
            loaded_model = joblib.load(file_path)
            if self._generate_model_hash(loaded_model) != self.model_hashes.get(model_name):
                raise ValueError("Model hash mismatch after saving")
                
            logger.info("Saved model '%s' to %s", model_name, file_path)
            return True
            
        except Exception as e:
            logger.error("Model save failed: %s", str(e))
            return False

    def load_model(self, file_path: str, model_name: str = None) -> bool:
        """Load trained model from disk"""
        try:
            model = joblib.load(file_path)
            
            # Use filename if no name provided
            if not model_name:
                model_name = Path(file_path).stem
                
            # Verify model type
            if not hasattr(model, 'predict'):
                raise ValueError("Invalid model object")
                
            # Store model
            self.models[model_name] = model
            self.model_hashes[model_name] = self._generate_model_hash(model)
            
            logger.info("Loaded model '%s' from %s", model_name, file_path)
            return True
            
        except Exception as e:
            logger.error("Model load failed: %s", str(e))
            return False

    # --------------------------
    # UTILITY METHODS
    # --------------------------
    
    def _resolve_dataset(self, dataset_name: str = None) -> Dict:
        """Get dataset by name or active dataset"""
        name_to_use = dataset_name or self.active_dataset
        if not name_to_use:
            logger.error("No dataset specified and no active dataset")
            return None
            
        if name_to_use not in self.datasets:
            logger.error("Dataset '%s' not found", name_to_use)
            return None
            
        return self.datasets[name_to_use]

    def get_performance_report(self) -> Dict:
        """Generate comprehensive performance report"""
        return {
            'timestamp': datetime.now().isoformat(),
            'best_model': self.best_model,
            'model_performance': self.model_performance,
            'active_dataset': self.active_dataset,
            'dataset_stats': {
                name: ds['stats'] for name, ds in self.datasets.items()
            }
        }

    def create_ensemble(self, model_names: List[str], ensemble_name: str,
                       method: str = 'voting') -> bool:
        """
        Create ensemble of models
        
        Args:
            model_names: List of model names to ensemble
            ensemble_name: Name for new ensemble
            method: Ensemble method ('voting', 'stacking')
            
        Returns:
            bool: True if successful
        """
        try:
            # Validate models
            valid_models = []
            for name in model_names:
                if name in self.models and name in self.model_performance:
                    valid_models.append((name, self.models[name]))
                else:
                    logger.warning("Skipping invalid model: %s", name)
                    
            if len(valid_models) < 2:
                raise ValueError("Need at least 2 valid models for ensemble")
                
            # Create ensemble
            if method == 'stacking':
                final_estimator = LogisticRegression()
                ensemble = StackingClassifier(
                    estimators=valid_models,
                    final_estimator=final_estimator,
                    cv=5
                )
            else:  # voting
                ensemble = VotingClassifier(
                    estimators=valid_models,
                    voting='soft'
                )
                
            # Store ensemble
            self.ensembles[ensemble_name] = ensemble
            logger.info("Created %s ensemble '%s' with %d models",
                      method, ensemble_name, len(valid_models))
            return True
            
        except Exception as e:
            logger.error("Ensemble creation failed: %s", str(e))
            return False

    def explain_prediction(self, features, model_name: str = None) -> Dict:
        """
        Generate explanation for a prediction (using SHAP or LIME)
        
        Args:
            features: Input features to explain
            model_name: Model to explain (best if None)
            
        Returns:
            Dict: Explanation results
        """
        try:
            model_to_use = model_name or self.best_model
            if not model_to_use:
                raise ValueError("No trained model available")
                
            # Placeholder - integrate with SHAP/LIME
            explanation = {
                'feature_importance': {},
                'decision_plot': None,
                'summary_plot': None
            }
            
            # Simple feature importance for tree models
            model = self.models[model_to_use]
            if hasattr(model, 'feature_importances_'):
                if hasattr(model, 'feature_names_in_'):
                    feature_names = model.feature_names_in_
                else:
                    feature_names = [f'feature_{i}' for i in range(len(model.feature_importances_))]
                    
                explanation['feature_importance'] = dict(zip(
                    feature_names,
                    model.feature_importances_
                ))
            
            return {
                'model': model_to_use,
                'explanation': explanation
            }
            
        except Exception as e:
            logger.error("Explanation failed: %s", str(e))
            return {
                'error': str(e)
            }
    def startup_sequence(components: dict, audit_logger) -> bool:
        """
        Perform system startup sequence and component verification
        
        Args:
            components: Dictionary of initialized system components
            audit_logger: Audit logger instance for security logging
            
        Returns:
            bool: True if all components started successfully, False otherwise
            
        Raises:
            ValueError: If required components are missing
            RuntimeError: If component initialization fails
        """
        # Validate input parameters
        if not isinstance(components, dict):
            logger.error("Invalid components parameter: expected dict")
            return False
            
        if not hasattr(audit_logger, 'log_event'):
            logger.error("Invalid audit_logger: missing log_event method")
            return False

        try:
            logger.info("🚀 Starting system initialization sequence...")
            audit_logger.log_event("SYSTEM_START", "Beginning startup sequence")

            # 1. Verify all critical components are present
            required_components = [
                'system_monitor',
                'network_analyzer', 
                'threat_intel',
                'ml_engine',
                'file_scanner',
                'quarantine_manager',
                'security_manager'
            ]
            
            missing_components = [
                comp for comp in required_components
                if comp not in components or components[comp] is None
            ]
            
            if missing_components:
                raise ValueError(
                    f"Missing required components: {', '.join(missing_components)}"
                )

            # 2. Initialize each component with dependency ordering
            initialization_order = [
                ('system_monitor', "System Monitor"),
                ('threat_intel', "Threat Intelligence"),
                ('network_analyzer', "Network Analyzer"),
                ('ml_engine', "ML Engine"),
                ('file_scanner', "File Scanner"),
                ('quarantine_manager', "Quarantine Manager"),
                ('security_manager', "Security Manager")
            ]

            for component, display_name in initialization_order:
                logger.debug(f"Initializing {display_name}...")
                start_time = time.time()
                
                comp_instance = components[component]
                if hasattr(comp_instance, 'initialize'):
                    if not comp_instance.initialize():
                        raise RuntimeError(f"{display_name} failed to initialize")
                        
                    audit_logger.log_event(
                        f"{component.upper()}_INIT",
                        f"{display_name} initialized in {time.time() - start_time:.2f}s"
                    )

            # 3. Verify cross-component dependencies
            if not components['ml_engine'].verify_dependencies():
                raise RuntimeError("ML Engine dependencies not satisfied")

            feed_status = components['threat_intel'].update_feeds()
            if not feed_status:
                logger.warning("Threat intelligence feeds not updated")
                audit_logger.log_event(
                    "THREAT_FEED_WARNING",
                    "Initial threat feed update failed"
                )
                
            logger.info("✅ System initialization completed successfully")
            audit_logger.log_event(
                "INIT_COMPLETE",
                f"All components initialized in {time.time() - start_time:.2f} seconds"
            )
            return True

        except ValueError as ve:
            logger.error(f"Configuration error: {str(ve)}")
            audit_logger.log_event("CONFIG_ERROR", str(ve))
            return False
            
        except RuntimeError as re:
            logger.critical(f"Runtime error during initialization: {str(re)}")
            audit_logger.log_event("INIT_FAILURE", str(re))
            return False
            
        except Exception as e:
            logger.critical(
                f"Unexpected startup error: {str(e)}",
                exc_info=True
            )
            audit_logger.log_event(
                "FATAL_ERROR",
                f"Unexpected startup failure: {str(e)}"
            )
            return False
    def verify_dependencies(self) -> bool:
        """
        Verifies all required ML dependencies, such as:
        - Required Python packages (scikit-learn, pandas, etc.)
        - Dataset availability
        - Model compatibility
        - Required files or configurations

        Returns:
            bool: True if all dependencies are valid, False otherwise.
        """
        try:
            import numpy
            logger.debug("NumPy import OK")
            import sklearn
            logger.debug("scikit-learn import OK")
            import pandas
            logger.debug("Pandas import OK")
            import joblib
            logger.debug("Joblib import OK")
            from imblearn.over_sampling import SMOTE
            from sklearn.ensemble import RandomForestClassifier

            # Check if at least one dataset is loaded
            if not self.datasets:
                logging.error("ML Engine dependency check failed: No datasets loaded.")
                return False
            if not self.datasets:
                logger.warning("No datasets loaded yet.")
                return False

            # Check for required label column in datasets
            for name, data in self.datasets.items():
                if 'features' not in data or 'labels' not in data:
                    logging.error(f"Dataset '{name}' is missing required structure.")
                    return False

            # Check model registry
            if not self.models:
                logging.error("ML Engine has no models registered.")
                return False

            logging.info("✅ ML Engine dependency check passed.")
            return True

        except ImportError as e:
            logging.critical(f"Missing ML dependency: {e.name}")
            return False

        except Exception as e:
            logging.critical(f"Unexpected error during ML dependency check: {str(e)}")
            return False
    def reload_model(self):
        try:
            if not self.model_path:
                raise ValueError("No model path set for reloading")
            self.model = joblib.load(self.model_path)
            print("✅ ML model reloaded.")
        except Exception as e:
            print(f"Failed to reload model: {e}")

    def train_all_models(self, dataset_name: str = None):
        """Train all models on the specified or active dataset"""
        results = {}
        skip_models = ['lof', 'one_class_svm', 'isolation_forest', 'kmeans', 'dbscan']

        for model_name in self.models:
            if model_name in skip_models:
                continue
            try:
                result = self.train_model(model_name, dataset_name=dataset_name)
                results[model_name] = result
            except Exception as e:
                results[model_name] = {'status': 'error', 'error': str(e)}

        return results
