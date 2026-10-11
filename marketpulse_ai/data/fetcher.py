"""Data module for fetching NSE stock data for MarketPulse AI."""
import yfinance as yf
import pandas as pd
from datetime import datetime, timedelta


class NSEDataFetcher:
    """Fetch NSE (National Stock Exchange of India) stock data."""
    
    @staticmethod
    def get_ticker_symbol(symbol: str, exchange: str = "NSE") -> str:
        """Convert symbol to yfinance ticker format."""
        symbol_map = {
            "TCS": "TCS.NS",
            "RELIANCE": "RELIANCE.NS",
            "INFY": "INFY.NS",
            "TATA MOTORS": "TATAMOTORS.NS",
            "SBI": "SBIN.NS",
            "HDFC": "HDFCBANK.NS",
            "ICICI": "ICICIBANK.NS",
        }
        if symbol.upper() in symbol_map:
            return symbol_map[symbol.upper()]
        # Default format
        return f"{symbol.upper()}.NS"
    
    @classmethod
    def fetch_stock_data(cls, 
                        symbol: str, 
                        period: str = "3mo", 
                        interval: str = "1d") -> pd.DataFrame:
        """
        Fetch historical stock data from NSE.
        :param symbol: Stock symbol (e.g., TCS, RELIANCE)
        :param period: Time period (1d, 5d, 1mo, 3mo, 6mo, 1y, 2y, 5y, 10y, ytd, max)
        :param interval: Data interval (1m, 2m, 5m, 15m, 30m, 60m, 90m, 1h, 1d, 5d, 1wk, 1mo, 3mo)
        :return: DataFrame with OHLCV data
        """
        ticker = cls.get_ticker_symbol(symbol)
        try:
            stock = yf.Ticker(ticker)
            df = stock.history(period=period, interval=interval)
            if df.empty:
                raise ValueError(f"No data found for {ticker}")
            # Ensure we have required columns
            df = df[['Open', 'High', 'Low', 'Close', 'Volume']].copy()
            df.reset_index(inplace=True)
            return df
        except Exception as e:
            raise RuntimeError(f"Error fetching data for {ticker}: {str(e)}")
    
    @classmethod
    def fetch_live_data(cls, symbol: str) -> dict:
        """Fetch latest live data for a stock."""
        ticker = cls.get_ticker_symbol(symbol)
        stock = yf.Ticker(ticker)
        info = stock.info
        df = stock.history(period="1d", interval="1m")
        
        if not df.empty:
            latest = df.iloc[-1]
            return {
                "symbol": symbol,
                "price": round(latest['Close'], 2),
                "change": round(latest['Close'] - df.iloc[0]['Close'], 2),
                "change_pct": round((latest['Close'] - df.iloc[0]['Close']) / df.iloc[0]['Close'] * 100, 2),
                "volume": int(latest['Volume']),
                "high": round(latest['High'], 2),
                "low": round(latest['Low'], 2),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        return {"symbol": symbol, "price": 0, "change": 0, "change_pct": 0, "volume": 0, "high": 0, "low": 0, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    
    @classmethod
    def get_nifty_50(cls) -> pd.DataFrame:
        """Fetch Nifty 50 index data."""
        return cls.fetch_stock_data("NIFTY", period="3mo", interval="1d")