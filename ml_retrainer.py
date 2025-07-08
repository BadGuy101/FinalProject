# engines/ml_retrainer.py

import pandas as pd
import joblib
import logging
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import (
    classification_report, 
    precision_recall_fscore_support,
    roc_auc_score
)
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

logger = logging.getLogger("ML_Engine.MLModelRetrainer")

class MLModelRetrainer:
    """Enhanced model retrainer with support for multiple threat types"""
    
    THREAT_COLUMNS = {
        'malware': ['file_size', 'entropy', 'imports', 'sections'],
        'adware': ['network_calls', 'popup_count', 'tracking_domains'],
        'ransomware': ['encryption_apis', 'file_operations', 'network_activity'],
        'malicious_website': ['js_functions', 'iframe_count', 'external_requests']
    }

    def __init__(self, feedback_path: str, model_output_dir: str):
        self.feedback_path = Path(feedback_path)
        self.model_output_dir = Path(model_output_dir)
        self.model_output_dir.mkdir(parents=True, exist_ok=True)
        self.threat_models = {}  # Track best models per threat type

    def retrain_from_feedback(self) -> Dict[str, bool]:
        """Retrain models for each threat type"""
        results = {}
        try:
            df = self._load_and_preprocess_feedback()
            
            if len(df) < 50:  # Minimum samples for retraining
                logger.warning(f"Insufficient feedback samples ({len(df)}). Need at least 50.")
                return {'status': False, 'reason': 'insufficient_samples'}
                
            # Train separate models for each threat type
            for threat_type in df['threat_type'].unique():
                threat_df = df[df['threat_type'] == threat_type]
                if len(threat_df) < 10:  # Skip if too few samples
                    continue
                    
                result = self._retrain_threat_model(threat_type, threat_df)
                results[threat_type] = result
                
            # Train a general model
            general_result = self._retrain_general_model(df)
            results['general'] = general_result
            
            return results
            
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
            return {'status': False, 'error': str(e)}

    def _retrain_threat_model(self, threat_type: str, df: pd.DataFrame) -> Dict:
        """Retrain model for specific threat type"""
        try:
            # Get relevant features for this threat type
            features = self.THREAT_COLUMNS.get(threat_type, []) + [
                'file_size', 'detections', 'threat_level'
            ]
            features = [f for f in features if f in df.columns]
            
            X = df[features]
            y = df['label'].map({'benign': 0, 'malicious': 1})
            
            # Split with 60/40 ratio
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.4, random_state=42, stratify=y
            )
            
            # Create pipeline with appropriate resampling
            pipeline = ImbPipeline([
                ('smote', SMOTE(random_state=42)),
                ('model', self._get_threat_model(threat_type))
            ])
            
            # Train and evaluate
            pipeline.fit(X_train, y_train)
            metrics = self._evaluate_model(pipeline, X_test, y_test)
            
            # Save model
            model_path = self.model_output_dir / f'model_{threat_type}.joblib'
            self._save_model(pipeline, threat_type, metrics, model_path)
            
            self.threat_models[threat_type] = {
                'model': pipeline,
                'metrics': metrics,
                'path': str(model_path)
            }
            
            return {
                'status': True,
                'threat_type': threat_type,
                'metrics': metrics,
                'samples': len(df)
            }
            
        except Exception as e:
            logger.error(f"Failed to retrain {threat_type} model: {e}")
            return {
                'status': False,
                'threat_type': threat_type,
                'error': str(e)
            }

    def _retrain_general_model(self, df: pd.DataFrame) -> Dict:
        """Retrain general-purpose threat detection model"""
        try:
            # Use all available features
            features = [col for col in df.columns if col not in ['label', 'threat_type']]
            X = df[features]
            y = df['label'].map({'benign': 0, 'malicious': 1})
            
            # 60/40 split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.4, random_state=42, stratify=y
            )
            
            # Create ensemble model
            estimators = [
                ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
                ('xgb', XGBClassifier(random_state=42)),
                ('lgbm', LGBMClassifier(random_state=42))
            ]
            
            pipeline = ImbPipeline([
                ('smote', SMOTE(random_state=42)),
                ('ensemble', VotingClassifier(estimators=estimators, voting='soft'))
            ])
            
            # Train and evaluate
            pipeline.fit(X_train, y_train)
            metrics = self._evaluate_model(pipeline, X_test, y_test)
            
            # Save model
            model_path = self.model_output_dir / 'model_general.joblib'
            self._save_model(pipeline, 'general', metrics, model_path)
            
            return {
                'status': True,
                'metrics': metrics,
                'samples': len(df)
            }
            
        except Exception as e:
            logger.error(f"Failed to retrain general model: {e}")
            return {
                'status': False,
                'error': str(e)
            }

    def _get_threat_model(self, threat_type: str):
        """Get appropriate model type for threat"""
        if threat_type == 'ransomware':
            return RandomForestClassifier(
                n_estimators=200,
                class_weight='balanced',
                max_depth=None,
                random_state=42
            )
        elif threat_type == 'adware':
            return LGBMClassifier(
                n_estimators=150,
                learning_rate=0.05,
                max_depth=-1,
                random_state=42
            )
        else:  # Default model
            return XGBClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            )

    def _evaluate_model(self, model, X_test, y_test) -> Dict:
        """Evaluate model performance"""
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='weighted'
        )
        
        return {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'roc_auc': roc_auc_score(y_test, y_proba),
            'report': classification_report(y_test, y_pred, output_dict=True)
        }

    def _save_model(self, model, threat_type: str, metrics: Dict, path: Path) -> None:
        """Save model with metadata"""
        metadata = {
            'threat_type': threat_type,
            'metrics': metrics,
            'timestamp': datetime.now().isoformat(),
            'version': '1.1'
        }
        
        joblib.dump({
            'model': model,
            'metadata': metadata
        }, path)
        
        logger.info(f"✅ Saved {threat_type} model to {path}")

    def _load_and_preprocess_feedback(self) -> pd.DataFrame:
        """Load and preprocess feedback data"""
        df = pd.read_csv(self.feedback_path)
        
        # Ensure required columns
        required_cols = ['file_path', 'label', 'threat_type', 'file_size', 'detections', 'threat_level']
        for col in required_cols:
            if col not in df.columns:
                raise ValueError(f"Missing required column: {col}")
                
        # Clean data
        df = df.dropna(subset=required_cols)
        df = df[df['label'].isin(['benign', 'malicious'])]
        
        # Convert detections to count if needed
        if df['detections'].dtype == object:
            df['detections'] = df['detections'].apply(lambda x: len(eval(x)) if isinstance(x, str) else 0)
            
        return df