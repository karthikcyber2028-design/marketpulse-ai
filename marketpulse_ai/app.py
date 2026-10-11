"""MarketPulse AI v2.0 - Main Application Entry Point."""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta

# Import MarketPulse AI modules
from marketpulse_ai.data.fetcher import NSEDataFetcher
from marketpulse_ai.indicators.technical import rsi, macd, ema, bollinger_bands, atr
from marketpulse_ai.signal_engine import SignalEngine
from marketpulse_ai.models.ensemble import EnsembleModel


# Page config
st.set_page_config(
    page_title="MarketPulse AI v2.0",
    page_icon="📈",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {font-size: 3rem; color: #1f77b4; margin-bottom: 1rem;}
    .signal-buy {color: #2ca02c; font-weight: bold; font-size: 1.5rem;}
    .signal-sell {color: #d62728; font-weight: bold; font-size: 1.5rem;}
    .signal-hold {color: #ff7f0e; font-weight: bold; font-size: 1.5rem;}
    .metric-card {background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin: 0.5rem 0;}
    .divider {border: 1px solid #e2e8f0; margin: 1rem 0;}
</style>
""", unsafe_allow_html=True)


def main():
    """Main application entry point."""
    st.title("📈 MarketPulse AI v2.0")
    st.markdown("**AI-powered stock market analysis and price prediction**")
    st.markdown("Ensemble model: XGBoost + LightGBM + LSTM + Technical Indicators")
    
    # Sidebar
    st.sidebar.header("Configuration")
    stock_symbol = st.sidebar.text_input("Stock Symbol", "TCS").upper()
    period = st.sidebar.selectbox("Data Period", ["1mo", "3mo", "6mo", "1y"], index=1)
    interval = st.sidebar.selectbox("Interval", ["1d", "1h"], index=0)
    
    # Fetch data
    with st.spinner("Fetching market data..."):
        try:
            fetcher = NSEDataFetcher()
            data = fetcher.fetch_stock_data(stock_symbol, period=period, interval=interval)
            live_data = fetcher.fetch_live_data(stock_symbol)
        except Exception as e:
            st.error(f"Error fetching data: {str(e)}")
            st.stop()
    
    # Calculate technical indicators
    with st.spinner("Calculating technical indicators..."):
        # RSI
        data['rsi'] = rsi(pd.Series(data['Close']), period=14)
        
        # MACD
        macd_line, macd_signal_line, macd_hist = macd(pd.Series(data['Close']))
        data['macd'] = macd_line
        data['macd_signal'] = macd_signal_line
        data['macd_hist'] = macd_hist
        
        # EMA
        data['ema_fast'] = ema(pd.Series(data['Close']), period=8)
        data['ema_slow'] = ema(pd.Series(data['Close']), period=21)
        
        # Bollinger Bands
        bb_upper, bb_middle, bb_lower = bollinger_bands(pd.Series(data['Close']), period=20)
        data['bb_upper'] = bb_upper
        data['bb_middle'] = bb_middle
        data['bb_lower'] = bb_lower
        
        # ATR
        data['atr'] = atr(pd.Series(data['High']), pd.Series(data['Low']), pd.Series(data['Close']), period=14)
    
    # Initialize signal engine
    signal_engine = SignalEngine()
    
    # Generate signal
    signal_data = signal_engine.generate_signal(data)
    
    # Initialize ensemble model
    with st.spinner("Running ensemble model..."):
        try:
            ensemble = EnsembleModel(weights=[1/3, 1/3, 1/3])
            # Train with available data (simplified)
            from sklearn.preprocessing import StandardScaler
            from sklearn.model_selection import train_test_split
            
            # Prepare features
            features = data[['Close', 'Open', 'High', 'Low', 'Volume', 'rsi', 'macd', 'ema_fast', 'ema_slow', 'bb_upper', 'bb_lower', 'atr']].copy()
            features = features.fillna(method='ffill').fillna(0)
            
            # Create target: 1=BUY, 0=HOLD, -1=SELL based on future price movement
            future_close = data['Close'].shift(-5)  # 5 days ahead
            price_change = (future_close - data['Close']) / data['Close']
            data['target'] = 0  # Default HOLD
            data.loc[price_change > 0.02, 'target'] = 1  # BUY if > 2% increase
            data.loc[price_change < -0.02, 'target'] = -1  # SELL if > 2% decrease
            
            # Split data
            X = features.iloc[:-5]  # Exclude last 5 rows for target calculation
            y = data['target'].iloc[:-5]
            
            if len(X) > 20:
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
                ensemble.fit(X_train, y_train)
                
                # Get ensemble prediction
                ensemble_signal, ensemble_proba = ensemble.predict(X_test.iloc[[-1]])
            else:
                ensemble_signal = "HOLD"
                ensemble_proba = {"BUY": 0.33, "HOLD": 0.33, "SELL": 0.33}
        except Exception as e:
            st.warning(f"Model training issue: {str(e)[:100]}")
            ensemble_signal = "HOLD"
            ensemble_proba = {"BUY": 0.33, "HOLD": 0.33, "SELL": 0.33}
    
    # Update signal with ensemble
    if ensemble_signal in ["BUY", "SELL", "HOLD"]:
        signal_data['ensemble_signal'] = ensemble_signal
        signal_data['ensemble_probability'] = ensemble_proba
    
    # Display results
    display_results(data, live_data, signal_data, stock_symbol)


def display_results(data, live_data, signal_data, symbol):
    """Display analysis results in Streamlit dashboard."""
    st.divider()
    
    # Header info
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Current Price", f"₹{live_data['price']}")
    with col2:
        st.metric("Change", f"₹{live_data['change']} ({live_data['change_pct']}%)")
    with col3:
        st.metric("Daily High", f"₹{live_data['high']}")
    with col4:
        st.metric("Daily Low", f"₹{live_data['low']}")
    
    # Signal display
    st.divider()
    st.subheader("🤖 MarketPulse AI Signal")
    
    signal = signal_data['signal']
    confidence = signal_data['confidence']
    
    # Color-coded signal
    signal_colors = {
        "BUY": "🟢 BUY",
        "SELL": "🔴 SELL", 
        "HOLD": "🟡 HOLD"
    }
    
    st.markdown(f"<h2 class='signal-{signal.lower()}'>{signal_colors[signal]}</h2>", unsafe_allow_html=True)
    st.markdown(f"**Confidence:** {confidence}%")
    
    # Ensemble info
    if signal_data.get('ensemble_signal'):
        st.caption(f"Ensemble Model: {signal_data['ensemble_signal']} "
                   f"(|BUY|{signal_data['ensemble_probability']['BUY']*100:.1f}% | "
                   f"|HOLD|{signal_data['ensemble_probability']['HOLD']*100:.1f}% | "
                   f"|SELL|{signal_data['ensemble_probability']['SELL']*100:.1f}%)")
    
    # Technical analysis breakdown
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Trend", signal_data['trend'])
        st.metric("RSI", signal_data['rsi'])
    with col2:
        st.metric("Momentum", signal_data['momentum'])
        st.metric("BB Position", signal_data['bb_position'])
    with col3:
        st.metric("ATR (Volatility)", signal_data['atr'])
        st.metric("Risk Level", signal_data['risk'])
    
    # Confidence breakdown
    st.caption(f"Signal Components: Trend={signal_data['trend']} | "
               f"Momentum={signal_data['momentum']} | "
               f"Volume Spike={signal_data['volume_spike']}")
    
    # Charts
    st.divider()
    st.subheader("📊 Price & Indicators Chart")
    
    # Price chart with indicators
    fig = go.Figure()
    
    # Candlestick
    fig.add_trace(go.Candlestick(
        x=data['Date'] if 'Date' in data.columns else range(len(data)),
        open=data['Open'],
        high=data['High'],
        low=data['Low'],
        close=data['Close'],
        name='Price'
    ))
    
    # Moving averages
    fig.add_trace(go.Scatter(
        x=data['Date'] if 'Date' in data.columns else range(len(data)),
        y=data['ema_fast'],
        name='EMA Fast (8)',
        line=dict(color='orange', width=1)
    ))
    
    fig.add_trace(go.Scatter(
        x=data['Date'] if 'Date' in data.columns else range(len(data)),
        y=data['ema_slow'],
        name='EMA Slow (21)',
        line=dict(color='blue', width=1)
    ))
    
    # Bollinger Bands
    fig.add_trace(go.Scatter(
        x=data['Date'] if 'Date' in data.columns else range(len(data)),
        y=data['bb_upper'],
        name='BB Upper',
        line=dict(color='gray', width=1, dash='dash')
    ))
    
    fig.add_trace(go.Scatter(
        x=data['Date'] if 'Date' in data.columns else range(len(data)),
        y=data['bb_lower'],
        name='BB Lower',
        line=dict(color='gray', width=1, dash='dash'),
        fill='toy0',
        fillcolor='rgba(128, 128, 128, 0.1)'
    ))
    
    fig.update_layout(
        title=f'{symbol} Price Chart with Technical Indicators',
        yaxis_title='Price (₹)',
        xaxis_title='Date',
        hovermode='x unified',
        template='plotly_white',
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # RSI Chart
    st.caption("RSI (Relative Strength Index)")
    fig_rsi = go.Figure()
    fig_rsi.add_trace(go.Scatter(
        y=data['rsi'], 
        name='RSI', 
        line=dict(color='purple', width=2)
    ))
    fig_rsi.add_hline(y=70, line_dash='dot', line_color='red', annotation_text='Overbought')
    fig_rsi.add_hline(y=30, line_dash='dot', line_color='green', annotation_text='Oversold')
    fig_rsi.add_hline(y=50, line_dash='dash', line_color='gray')
    fig_rsi.update_layout(
        title='RSI Indicator',
        template='plotly_white',
        height=300
    )
    st.plotly_chart(fig_rsi, use_container_width=True)
    
    # MACD Chart
    fig_macd = go.Figure()
    fig_macd.add_trace(go.Scatter(y=data['macd'], name='MACD', line=dict(color='blue', width=1)))
    fig_macd.add_trace(go.Scatter(y=data['macd_signal'], name='Signal', line=dict(color='red', width=1)))
    fig_macd.add_trace(go.Bar(y=data['macd_hist'], name='Histogram', marker_color='gray'))
    fig_macd.update_layout(
        title='MACD Indicator',
        template='plotly_white',
        height=300
    )
    st.plotly_chart(fig_macd, use_container_width=True)
    
    # Backtesting
    st.divider()
    st.subheader("🧪 Backtest Analysis")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Run Backtest", type="primary"):
            with st.spinner("Running backtest..."):
                backtest = BacktestEngine(initial_capital=100000)
                results = backtest.run_backtest(data)
                
                st.metric("Final Capital", f"₹{results['final_capital']:,.0f}")
                st.metric("Total Return", f"{results['total_return_pct']}%")
                st.metric("Buy & Hold Return", f"{results['buy_hold_return_pct']}%")
                st.metric("Win Rate", f"{results['win_rate']}%")
                st.metric("Profit Factor", f"{results['profit_factor']}")
                st.metric("Max Drawdown", f"{results['max_drawdown_pct']}%")
                st.metric("Total Trades", f"{results['total_trades']}")
    
    with col2:
        st.caption("Backtest compares AI signal performance against simple buy & hold strategy over the selected period.")
    
    # Risk warning
    st.divider()
    st.warning("""
    ⚠️ **Risk Disclaimer**: MarketPulse AI provides probability-based signals for educational purposes only. 
    No AI model can reliably predict exact future stock prices. All trading decisions should be made with proper 
    risk management and only with capital you can afford to lose. Past performance does not guarantee future results.
    """)


if __name__ == "__main__":
    main()