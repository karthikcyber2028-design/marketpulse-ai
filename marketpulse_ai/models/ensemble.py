"""ML models for MarketPulse AI v2.0 Ensemble."""
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, List


class BaseModel:
    """Base class for all models."""
    
    def __init__(self, name: str):
        self.name = name
        self.model = None
        self.trained = False
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'BaseModel':
        raise NotImplementedError
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        raise NotImplementedError
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        raise NotImplementedError


class XGBoostModel(BaseModel):
    """XGBoost model for BUY/SELL classification."""
    
    def __init__(self, name: str = "XGBoost"):
        super().__init__(name)
        try:
            import xgboost as xgb
            self.xgb = xgb
        except ImportError:
            self.xgb = None
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'XGBoostModel':
        if self.xgb is None:
            raise ImportError("xgboost not installed")
        from xgboost import XGBClassifier
        self.model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            objective="multi:softprob",
            num_class=3,
            random_state=42
        )
        self.model.fit(X, y)
        self.trained = True
        return self
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        if not self.trained or self.model is None:
            raise ValueError("Model not trained yet")
        return self.model.predict(X)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        if not self.trained or self.model is None:
            raise ValueError("Model not trained yet")
        return self.model.predict_proba(X)


class LightGBMModel(BaseModel):
    """LightGBM model for BUY/SELL classification."""
    
    def __init__(self, name: str = "LightGBM"):
        super().__init__(name)
        try:
            import lightgbm as lgb
            self.lgb = lgb
        except ImportError:
            self.lgb = None
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'LightGBMModel':
        if self.lgb is None:
            raise ImportError("lightgbm not installed")
        from lightgbm import LGBMClassifier
        self.model = LGBMClassifier(
            n_estimators=100,
            max_depth=-1,
            learning_rate=0.1,
            num_class=3,
            random_state=42,
            verbosity=-1
        )
        self.model.fit(X, y)
        self.trained = True
        return self
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        if not self.trained or self.model is None:
            raise ValueError("Model not trained yet")
        return self.model.predict(X)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        if not self.trained or self.model is None:
            raise ValueError("Model not trained yet")
        return self.model.predict_proba(X)


class LSTMModel(BaseModel):
    """LSTM model for price movement prediction."""
    
    def __init__(self, name: str = "LSTM", sequence_length: int = 30):
        super().__init__(name)
        self.sequence_length = sequence_length
        self.model = None
        self.scaler = None
    
    def _create_sequences(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        X, y = [], []
        for i in range(self.sequence_length, len(data)):
            X.append(data[i-self.sequence_length:i])
            y.append(data[i, 0])  # Using first feature as target
        return np.array(X), np.array(y)
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'LSTMModel':
        try:
            import tensorflow as tf
            from sklearn.preprocessing import MinMaxScaler
            tf = __import__('tensorflow')
            self.scaler = MinMaxScaler()
            data = self.scaler.fit_transform(X.values.reshape(-1, 1) if X.ndim == 1 else X).flatten()
            X_seq, y_seq = self._create_sequences(data)
            self.model = tf.keras.Sequential([
                tf.keras.layers.LSTM(50, return_sequences=True, input_shape=(X_seq.shape[1], X_seq.shape[2])),
                tf.keras.layers.LSTM(50),
                tf.keras.layers.Dense(3, activation='softmax')
            ])
            self.model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
            y_cat = pd.get_dummies(y).values
            self.model.fit(X_seq, y_cat, epochs=20, batch_size=32, verbose=0)
            self.trained = True
        except ImportError:
            raise ImportError("tensorflow not installed")
        return self
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        if not self.trained or self.model is None:
            raise ValueError("LSTM model not trained yet")
        # Simplified prediction - return probabilities
        return np.array([ [0.33, 0.33, 0.33] ] * len(X))
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        if not self.trained or self.model is None:
            raise ValueError("LSTM model not trained yet")
        return self.predict(X)


class EnsembleModel:
    """Ensemble model combining XGBoost, LightGBM, and LSTM predictions."""
    
    def __init__(self, weights: List[float] = None):
        self.models = {
            'xgboost': XGBoostModel('XGBoost'),
            'lightgbm': LightGBMModel('LightGBM'),
            'lstm': LSTMModel('LSTM')
        }
        if weights is None:
            self.weights = [1/3, 1/3, 1/3]  # Equal weights
        else:
            self.weights = weights
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'EnsembleModel':
        # Train tree-based models
        self.models['xgboost'].fit(X, y)
        self.models['lightgbm'].fit(X, y)
        # LSTM requires different formatting, skip or mark as untrained
        self.models['lstm'].trained = False
        
        # Calculate weights based on historical performance (simplified)
        self.weights = [1/3, 1/3, 1/3]
        return self
    
    def predict(self, X: pd.DataFrame) -> Tuple[str, Dict[str, float]]:
        """
        Predict BUY/HOLD/SELL signal with probabilities.
        Returns: (signal, probabilities_dict)
        """
        # Get predictions from each model
        xgb_proba = self.models['xgboost'].predict_proba(X) if self.models['xgboost'].trained else np.array([[1/3, 1/3, 1/3]])
        lgb_proba = self.models['lightgbm'].predict_proba(X) if self.models['lightgbm'].trained else np.array([[1/3, 1/3, 1/3]])
        
        # For LSTM, use equal weight since it's not fully trained in this prototype
        lstm_proba = np.array([[1/3, 1/3, 1/3]])
        
        # Weighted average
        ensemble_proba = (
            self.weights[0] * xgb_proba +
            self.weights[1] * lgb_proba +
            self.weights[2] * lstm_proba
        )
        
        # Map to signals: 0=SELL, 1=HOLD, 2=BUY
        signal_idx = int(np.argmax(ensemble_proba))
        signals = {0: "SELL", 1: "HOLD", 2: "BUY"}
        
        # Probability dict
        proba_dict = {
            "BUY": float(ensemble_proba[0][2]),
            "HOLD": float(ensemble_proba[0][1]),
            "SELL": float(ensemble_proba[0][0])
        }
        
        return signals[signal_idx], proba_dict
    
    def get_feature_importance(self) -> Dict[str, Any]:
        """Get combined feature importance from tree-based models."""
        importance = {}
        if self.models['xgboost'].trained and self.models['xgboost'].model is not None:
            for feat, imp in zip(X_train.columns if 'X_train' in dir() else [], self.models['xgboost'].model.feature_importances_):
                importance[feat] = imp
        if self.models['lightgbm'].trained and self.models['lightgbm'].model is not None:
            # LightGBM feature importance - try to get from model if available
            try:
                lgb_imp = dict(zip(self.models['lightgbm'].model.feature_name(), self.models['lightgbm'].model.feature_importance()))
                for feat, imp in lgb_imp.items():
                    importance[feat] = importance.get(feat, 0) + imp
            except:
                pass
        return importance