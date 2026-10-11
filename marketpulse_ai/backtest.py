"""Backtesting module for MarketPulse AI v2.0."""
import numpy as np
import pandas as pd
from .signal_engine import SignalEngine


class BacktestEngine:
    """Backtests MarketPulse AI signals against historical data."""
    
    def __init__(self, 
                 initial_capital: float = 100000.0,
                 transaction_cost_pct: float = 0.1,
                 slippage_pct: float = 0.05):
        self.initial_capital = initial_capital
        self.transaction_cost_pct = transaction_cost_pct / 100
        self.slippage_pct = slippage_pct / 100
        self.signal_engine = SignalEngine()
    
    def _calculate_return(self, 
                         entries: list, 
                         exits: list, 
                         signal_directions: list) -> float:
        """Calculate portfolio return from a series of trades."""
        capital = self.initial_capital
        positions = 0
        
        for i in range(len(entries)):
            entry = entries[i]
            exit_price = exits[i]
            direction = signal_directions[i]
            
            # Calculate P&L
            if direction == "BUY":
                # Buy at entry, sell at exit
                pnl_pct = (exit_price - entry) / entry
            elif direction == "SELL":
                # Sell short at entry, buy at exit
                pnl_pct = (entry - exit_price) / entry
            else:
                # HOLD - no trade
                continue
            
            # Apply costs
            cost_pct = self.transaction_cost_pct + self.slippage_pct
            pnl_adj = pnl_pct - cost_pct
            
            # Update capital
            capital *= (1 + pnl_adj)
            positions += 1
        
        return capital - self.initial_capital, capital
    
    def run_backtest(self, 
                    data: pd.DataFrame, 
                    signal_column: str = 'signal',
                    signal_threshold: float = 50.0) -> dict:
        """
        Run backtest on historical data.
        Returns performance metrics.
        """
        if signal_column not in data.columns:
            # Generate signals if not present
            from .signal_engine import SignalEngine
            engine = SignalEngine()
            # We'll need complete data for signal generation
            # For now, use a simple approach
            data = data.copy()
            data['close'] = data['close']
            data['high'] = data['high']
            data['low'] = data['low']
            data['volume'] = data['volume']
        
        # Generate signals
        signal_data = self.signal_engine.generate_signal(data)
        final_signal = signal_data['signal']
        
        # Simple backtest: hold signal for next period
        capital = self.initial_capital
        trades = []
        
        # Iterate through data with signal lookahead
        for i in range(1, len(data)):
            # Current signal
            current_signal = data[signal_column].iloc[i] if signal_column in data.columns else "HOLD"
            
            # Entry price at current bar
            entry_price = data['close'].iloc[i]
            
            # Exit price at next bar (simplified)
            if i < len(data) - 1:
                exit_price = data['close'].iloc[i + 1]
            else:
                exit_price = entry_price
            
            # Determine trade direction from signal
            direction = current_signal
            
            # Calculate P&L
            if direction == "BUY":
                pnl_pct = (exit_price - entry_price) / entry_price
            elif direction == "SELL":
                pnl_pct = (entry_price - exit_price) / entry_price
            else:
                pnl_pct = 0
            
            # Apply costs
            cost_pct = self.transaction_cost_pct + self.slippage_pct
            pnl_adj = pnl_pct - cost_pct
            
            # Update capital
            capital *= (1 + pnl_adj)
            
            trades.append({
                'entry_idx': i,
                'entry_price': entry_price,
                'exit_price': exit_price,
                'signal': direction,
                'pnl_pct': pnl_pct,
                'pnl_adj': pnl_adj,
                'capital_after': capital
            })
        
        total_return = capital - self.initial_capital
        total_return_pct = (capital / self.initial_capital - 1) * 100
        
        # Calculate buy & hold return for comparison
        first_price = data['close'].iloc[0]
        last_price = data['close'].iloc[-1]
        buy_hold_return = (last_price / first_price - 1) * 100
        buy_hold_capital = self.initial_capital * (1 + buy_hold_return / 100)
        
        # Calculate metrics
        winning_trades = [t for t in trades if t['pnl_adj'] > 0]
        losing_trades = [t for t in trades if t['pnl_adj'] <= 0]
        
        win_rate = len(winning_trades) / len(trades) if len(trades) > 0 else 0
        avg_win = np.mean([t['pnl_adj'] for t in winning_trades]) if winning_trades else 0
        avg_loss = np.mean([t['pnl_adj'] for t in losing_trades]) if losing_trades else 0
        
        # Gross profit/loss
        gross_profit = sum(t['pnl_adj'] for t in winning_trades)
        gross_loss = abs(sum(t['pnl_adj'] for t in losing_trades))
        
        profit_factor = gross_profit / gross_loss if gross_loss > 0 else float('inf')
        
        # Max drawdown
        equity_curve = [self.initial_capital]
        for t in trades:
            equity_curve.append(equity_curve[-1] * (1 + t['pnl_adj']))
        
        peak = self.initial_capital
        max_drawdown = 0
        for val in equity_curve:
            if val > peak:
                peak = val
            drawdown = (peak - val) / peak * 100
            max_drawdown = max(max_drawdown, drawdown)
        
        return {
            'initial_capital': self.initial_capital,
            'final_capital': round(capital, 2),
            'total_return': round(total_return, 2),
            'total_return_pct': round(total_return_pct, 2),
            'buy_hold_final': round(buy_hold_capital, 2),
            'buy_hold_return_pct': round(buy_hold_return, 2),
            'total_trades': len(trades),
            'winning_trades': len(winning_trades),
            'losing_trades': len(losing_trades),
            'win_rate': round(win_rate * 100, 2),
            'avg_win': round(avg_win * 100, 2),
            'avg_loss': round(avg_loss * 100, 2),
            'profit_factor': round(profit_factor, 2),
            'max_drawdown_pct': round(max_drawdown, 2),
            'trades': trades
        }