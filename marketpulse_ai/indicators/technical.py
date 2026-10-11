"""Technical indicators for MarketPulse AI v2.0."""
import pandas as pd
import numpy as np


def rsi(close: pd.Series, period: int = 14) -> pd.Series:
    """Relative Strength Index."""
    delta = close.diff()
    gain = (delta.where(delta > 0, 0)).fillna(0)
    loss = (-delta.where(delta < 0, 0)).fillna(0)
    avg_gain = gain.rolling(window=period).mean()
    avg_loss = loss.rolling(window=period).mean()
    rs = avg_gain / avg_loss
    rsi_val = 100 - (100 / (1 + rs))
    return rsi_val


def macd(close: pd.Series, fast: int = 12, slow: int = 26, signal: int = 9) -> tuple:
    """Moving Average Convergence Divergence."""
    fast_ema = close.ewm(span=fast, adjust=False).mean()
    slow_ema = close.ewm(span=slow, adjust=False).mean()
    macd_line = fast_ema - slow_ema
    signal_line = macd_line.ewm(span=signal, adjust=False).mean()
    histogram = macd_line - signal_line
    return macd_line, signal_line, histogram


def ema(close: pd.Series, period: int = 20) -> pd.Series:
    """Exponential Moving Average."""
    return close.ewm(span=period, adjust=False).mean()


def bollinger_bands(close: pd.Series, period: int = 20, std: float = 2.0) -> tuple:
    """Bollinger Bands."""
    sma = close.rolling(window=period).mean()
    std_dev = close.rolling(window=period).std()
    upper = sma + (std_dev * std)
    lower = sma - (std_dev * std)
    return upper, sma, lower


def atr(high: pd.Series, low: pd.Series, close: pd.Series, period: int = 14) -> pd.Series:
    """Average True Range."""
    tr = pd.concat([
        high - low,
        (high - close.shift()).abs(),
        (low - close.shift()).abs()
    ], axis=1).max(axis=1)
    return tr.rolling(window=period).mean()


def williams_r(high: pd.Series, low: pd.Series, close: pd.Series, period: int = 14) -> pd.Series:
    """Williams %R."""
    highest_high = high.rolling(window=period).max()
    lowest_low = low.rolling(window=period).min()
    wr = ((highest_high - close) / (highest_high - lowest_low)) * -100
    return wr


def adx(high: pd.Series, low: pd.Series, close: pd.Series, period: int = 14) -> pd.Series:
    """Average Directional Index."""
    plus_dm = high.diff().where((high.diff() > low.diff()) & (high.diff() > 0), 0)
    minus_dm = (-low.diff()).where(((-low.diff()) > (high.diff())) & (-low.diff() > 0), 0)
    tr = pd.concat([
        high - low,
        (high - close.shift()).abs(),
        (low - close.shift()).abs()
    ], axis=1).max(axis=1)
    plus_di = 100 * (plus_dm.rolling(window=period).mean() / tr.rolling(window=period).mean())
    minus_di = 100 * (minus_dm.rolling(window=period).mean() / tr.rolling(window=period).mean())
    dx = 100 * abs(plus_di - minus_di) / (plus_di + minus_di)
    return dx.rolling(window=period).mean()


def obv(close: pd.Series, volume: pd.Series) -> pd.Series:
    """On-Balance Volume."""
    price_change = close.diff()
    volume_signals = np.where(price_change > 0, volume, np.where(price_change < 0, -volume, 0))
    return volume_signals.cumsum()


def cci(high: pd.Series, low: pd.Series, close: pd.Series, period: int = 14) -> pd.Series:
    """Commodity Channel Index."""
    typical_price = (high + low + close) / 3
    sma_tp = typical_price.rolling(window=period).mean()
    mad = typical_price.rolling(window=period).apply(lambda x: np.mean(np.abs(x - np.mean(x))), raw=True)
    return (typical_price - sma_tp) / (0.015 * mad)