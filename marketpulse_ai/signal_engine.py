"""Signal engine for MarketPulse AI v2.0 - generates BUY/HOLD/SELL signals."""
import numpy as np
import pandas as pd
from .indicators.technical import rsi, macd, ema, bollinger_bands, atr, williams_r, adx, obv, cci


class SignalEngine:
    """Generates trading signals based on technical indicators and ensemble model."""
    
    def __init__(self, 
                 rsi_overbought: float = 70,
                 rsi_oversold: float = 30,
                 macd_fast: int = 12,
                 macd_slow: int = 26,
                 macd_signal: int = 9,
                 ema_fast: int = 8,
                 ema_slow: int = 21,
                 bb_std: float = 2.0):
        self.rsi_overbought = rsi_overbought
        self.rsi_oversold = rsi_oversold
        self.macd_fast = macd_fast
        self.macd_slow = macd_slow
        self.macd_signal = macd_signal
        self.ema_fast = ema_fast
        self.ema_slow = ema_slow
        self.bb_std = bb_std
    
    def _normalize_column(self, data: pd.DataFrame, column: str) -> pd.Series:
        """Get column from DataFrame case-insensitively."""
        column_lower = column.lower()
        for col in data.columns:
            if col.lower() == column_lower:
                return data[col]
        # Try exact match
        return data[column]
    
    def analyze_trend(self, close: pd.Series, fast_ema: pd.Series, slow_ema: pd.Series) -> str:
        """Analyze trend direction."""
        if fast_ema.iloc[-1] > slow_ema.iloc[-1]:
            return "BULLISH"
        elif fast_ema.iloc[-1] < slow_ema.iloc[-1]:
            return "BEARISH"
        else:
            return "NEUTRAL"
    
    def analyze_momentum(self, rsi_value: float) -> str:
        """Analyze momentum based on RSI."""
        if rsi_value > self.rsi_overbought:
            return "WEAK / OVERBOUGHT"
        elif rsi_value < self.rsi_oversold:
            return "WEAK / OVERSOLD"
        elif rsi_value > 50:
            return "STRONG BULLISH"
        elif rsi_value < 50:
            return "STRONG BEARISH"
        else:
            return "NEUTRAL"
    
    def analyze_bb_position(self, close: float, upper: float, lower: float) -> str:
        """Analyze Bollinger Band position."""
        if close > upper:
            return "ABOVE UPPER BAND - EXTREME"
        elif close < lower:
            return "BELOW LOWER BAND - EXTREME"
        elif close > (upper + lower) / 2:
            return "UPPER HALF"
        else:
            return "LOWER HALF"
    
    def generate_signal(self, 
                       data: pd.DataFrame,
                       ensemble_signal: str = None,
                       ensemble_probability: float = None) -> dict:
        """
        Generate BUY/HOLD/SELL signal based on technical analysis and ensemble.
        Returns signal dict with components.
        """
        close = self._normalize_column(data, 'close')
        high = self._normalize_column(data, 'high')
        low = self._normalize_column(data, 'low')
        volume = self._normalize_column(data, 'volume')
        
        # Calculate indicators
        rsi_val = rsi(close).iloc[-1]
        macd_line, signal_line, histogram = macd(close)
        macd_hist = histogram.iloc[-1]
        fast_ema = ema(close, self.ema_fast)
        slow_ema = ema(close, self.ema_slow)
        upper, middle, lower = bollinger_bands(close, std=self.bb_std)
        current_bb = self.analyze_bb_position(close.iloc[-1], upper.iloc[-1], lower.iloc[-1])
        atr_val = atr(high, low, close).iloc[-1]
        
        # Trend analysis
        trend = self.analyze_trend(close, fast_ema, slow_ema)
        
        # Momentum analysis
        momentum = self.analyze_momentum(rsi_val)
        
        # Volume analysis (simple)
        vol_current = volume.iloc[-1]
        vol_prev = volume.iloc[-2] if len(volume) > 1 else volume.iloc[-1]
        volume_spike = vol_current > vol_prev * 1.5 if vol_prev > 0 else False
        
        # Initialize scores
        buy_score = 0
        sell_score = 0
        hold_score = 0
        
        # Technical analysis contributions
        # RSI contribution
        if rsi_val > 70:
            sell_score += 2
        elif rsi_val < 30:
            buy_score += 2
        elif rsi_val > 50:
            buy_score += 1
        elif rsi_val < 50:
            sell_score += 1
        
        # Trend contribution
        if trend == "BULLISH":
            buy_score += 2
        elif trend == "BEARISH":
            sell_score += 2
        
        # MACD contribution
        if macd_hist > 0:
            buy_score += 1
        else:
            sell_score += 1
        
        # Bollinger Band contribution
        if current_bb == "ABOVE UPPER BAND - EXTREME":
            sell_score += 2
        elif current_bb == "BELOW LOWER BAND - EXTREME":
            buy_score += 2
        elif current_bb == "UPPER HALF":
            buy_score += 1
        elif current_bb == "LOWER HALF":
            sell_score += 1
        
        # Ensemble signal contribution (if provided)
        if ensemble_signal == "BUY":
            buy_score += 3
        elif ensemble_signal == "SELL":
            sell_score += 3
        elif ensemble_signal == "HOLD":
            hold_score += 3
        
        # Determine final signal
        total_score = buy_score + sell_score + hold_score
        
        if total_score == 0:
            final_signal = "HOLD"
            confidence = 50.0
        elif buy_score > sell_score and buy_score > hold_score:
            final_signal = "BUY"
            confidence = round(buy_score / total_score * 100, 1)
        elif sell_score > buy_score and sell_score > hold_score:
            final_signal = "SELL"
            confidence = round(sell_score / total_score * 100, 1)
        else:
            final_signal = "HOLD"
            confidence = round(hold_score / total_score * 100, 1)
        
        # Risk assessment
        risk = "MODERATE"
        if atr_val > close.iloc[-1] * 0.03:
            risk = "HIGH"
        elif atr_val < close.iloc[-1] * 0.01:
            risk = "LOW"
        
        signal = {
            "signal": final_signal,
            "confidence": confidence,
            "trend": trend,
            "momentum": momentum,
            "rsi": round(rsi_val, 2),
            "bb_position": current_bb,
            "atr": round(atr_val, 2),
            "risk": risk,
            "volume_spike": volume_spike,
            "ensemble_signal": ensemble_signal,
            "ensemble_probability": ensemble_probability
        }
        
        return signal