# tests/test_ml_engine.py

import unittest
import numpy as np
from engines.ml_engine import AdvancedMLEngine
from engines.file_scanner import AdvancedFileScanner
import tempfile
import os

class TestAdvancedMLEngine(unittest.TestCase):

    def setUp(self):
        self.engine = AdvancedMLEngine()
        self.scanner = AdvancedFileScanner()
        self.X = np.random.rand(10, 5)  # 10 samples, 5 features each
        self.y = np.random.choice([0, 1], size=(10,))  # Binary labels: 0 = benign, 1 = malicious

    def test_train_model_sets_is_trained(self):
        self.engine.train_model(self.X, self.y, model_type="random_forest")
        self.assertTrue(self.engine.is_trained, "Model should be marked as trained after training.")

    def test_predict_returns_0_or_1(self):
        self.engine.train_model(self.X, self.y, model_type="random_forest")
        prediction = self.engine.predict(self.X[0])
        self.assertIn(prediction, [0, 1], "Prediction must be either 0 (benign) or 1 (malicious).")

    def test_train_model_invalid_input_raises(self):
        with self.assertRaises(ValueError):
            self.engine.train_model([], [], model_type="random_forest")  # Invalid data

    def test_pipeline_extract_train_predict(self):
        # Create a fake file and extract features using AdvancedFileScanner
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write("sample executable fake content")
            tmp_path = tmp.name

        features = self.scanner.extract_features(tmp_path)
        os.unlink(tmp_path)  # cleanup after feature extraction

        self.assertIsInstance(features, dict)
        self.assertGreater(len(features), 0)

        # Convert to vector for ML prediction
        vector = np.array(list(features.values())).reshape(1, -1)
        self.engine.train_model(self.X, self.y, model_type="random_forest")
        pred = self.engine.predict(vector[0])
        self.assertIn(pred, [0, 1])

    def tearDown(self):
        pass

