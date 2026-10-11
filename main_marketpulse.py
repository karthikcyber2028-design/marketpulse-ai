"""MarketPulse AI v2.0 - Main Entry Point."""
import streamlit as st

st.set_page_config(page_title="MarketPulse AI v2.0", layout="wide")
st.title("📈 MarketPulse AI v2.0")
st.markdown("AI-powered stock market analysis and prediction")

st.sidebar.header("Settings")
symbol = st.sidebar.text_input("Stock Symbol", "TCS").upper()

st.sidebar.info(f"Analyzing: {symbol}")
st.write(f"Welcome to MarketPulse AI v2.0 - Ensemble Model")
st.write("This project demonstrates AI-powered stock market analysis with:")
st.markdown("- XGBoost + LightGBM + LSTM ensemble")
st.markdown("- Technical indicators: RSI, MACD, EMA, Bollinger Bands, ATR")
st.markdown("- BUY / HOLD / SELL signals with probability scores")
st.markdown("- Backtesting against buy & hold strategy")
st.markdown("- Interactive Streamlit dashboard")

st.markdown("---")
st.caption("⚠️ For educational purposes only. Not financial advice.")