import React, { useEffect, useState, useRef } from 'react';
import { View, Text, StyleSheet, Dimensions, Platform } from 'react-native';
import { WebView } from 'react-native-webview';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { DEBUG_MODE } from '../config';

interface ChartProps {
  data: any[];
  type: 'spending' | 'income' | 'budget' | 'category';
  height?: number;
}

interface ChartDataPoint {
  label: string;
  value: number;
  color?: string;
}

export const Chart: React.FC<ChartProps> = ({ data, type, height = 250 }) => {
  const [chartData, setChartData] = useState<ChartDataPoint[]>([]);
  const webViewRef = useRef<any>(null);
  const screenWidth = Dimensions.get('window').width - 32;

  useEffect(() => {
    processData();
  }, [data, type]);

  const processData = () => {
    if (!data || data.length === 0) return;

    let processed: ChartDataPoint[] = [];

    switch (type) {
      case 'spending': {
        const grouped = data.reduce((acc: Record<string, number>, tx: any) => {
          if (tx.type === 'debit') {
            const date = new Date(tx.date).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
            });
            acc[date] = (acc[date] || 0) + Math.abs(tx.amount);
          }
          return acc;
        }, {});
        processed = Object.entries(grouped).map(([label, value]) => ({
          label,
          value: value as number,
          color: '#2196F3',
        }));
        break;
      }
      case 'category': {
        const grouped = data.reduce((acc: Record<string, number>, tx: any) => {
          acc[tx.category] = (acc[tx.category] || 0) + Math.abs(tx.amount);
          return acc;
        }, {});
        const colors = ['#f44336', '#2196F3', '#4caf50', '#ff9800', '#9c27b0', '#00bcd4'];
        processed = Object.entries(grouped).map(([label, value], idx) => ({
          label,
          value: value as number,
          color: colors[idx % colors.length],
        }));
        break;
      }
      case 'income': {
        const grouped = data.reduce((acc: Record<string, number>, tx: any) => {
          if (tx.type === 'credit') {
            const date = new Date(tx.date).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
            });
            acc[date] = (acc[date] || 0) + tx.amount;
          }
          return acc;
        }, {});
        processed = Object.entries(grouped).map(([label, value]) => ({
          label,
          value: value as number,
          color: '#4caf50',
        }));
        break;
      }
      case 'budget': {
        processed = data.map((item: any) => ({
          label: item.category,
          value: (item.spent / item.limit) * 100,
          color: item.spent > item.limit ? '#f44336' : '#4caf50',
        }));
        break;
      }
    }

    setChartData(processed);
  };

  // BUG-0097: Chart renders via WebView with inline HTML/JS — user-controlled data (merchant names, categories) injected unsanitized into HTML (CWE-79, CVSS 6.1, TRICKY, Tier 1)
  const generateChartHtml = () => {
    const labels = chartData.map((d) => d.label);
    const values = chartData.map((d) => d.value);
    const colors = chartData.map((d) => d.color || '#2196F3');

    // BUG-0098: User-controlled transaction data (labels) injected directly into script — XSS in WebView context (CWE-79, CVSS 6.1, TRICKY, Tier 1)
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { margin: 0; padding: 8px; font-family: -apple-system, sans-serif; background: #fff; }
          .chart-container { width: 100%; height: ${height - 20}px; position: relative; }
          .bar-chart { display: flex; align-items: flex-end; justify-content: space-around; height: 80%; padding: 0 4px; }
          .bar-group { display: flex; flex-direction: column; align-items: center; flex: 1; margin: 0 2px; }
          .bar { width: 100%; max-width: 40px; border-radius: 4px 4px 0 0; transition: height 0.3s; min-height: 2px; }
          .bar-label { font-size: 10px; color: #666; margin-top: 4px; text-align: center; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 60px; }
          .bar-value { font-size: 10px; color: #333; font-weight: 600; margin-bottom: 2px; }
          .title { font-size: 14px; color: #333; font-weight: 600; margin-bottom: 8px; }
        </style>
      </head>
      <body>
        <div class="chart-container">
          <div class="bar-chart" id="chart"></div>
        </div>
        <script>
          const labels = ${JSON.stringify(labels)};
          const values = ${JSON.stringify(values)};
          const colors = ${JSON.stringify(colors)};
          const maxValue = Math.max(...values, 1);
          const chart = document.getElementById('chart');

          labels.forEach((label, i) => {
            const group = document.createElement('div');
            group.className = 'bar-group';

            const valueEl = document.createElement('div');
            valueEl.className = 'bar-value';
            valueEl.textContent = '$' + values[i].toFixed(0);

            const bar = document.createElement('div');
            bar.className = 'bar';
            bar.style.height = ((values[i] / maxValue) * 100) + '%';
            bar.style.backgroundColor = colors[i];

            const labelEl = document.createElement('div');
            labelEl.className = 'bar-label';
            labelEl.innerHTML = label;

            group.appendChild(valueEl);
            group.appendChild(bar);
            group.appendChild(labelEl);
            chart.appendChild(group);
          });

          // Send chart interaction events to RN
          chart.addEventListener('click', (e) => {
            const group = e.target.closest('.bar-group');
            if (group) {
              const idx = Array.from(chart.children).indexOf(group);
              window.ReactNativeWebView.postMessage(JSON.stringify({
                type: 'chart_tap',
                index: idx,
                label: labels[idx],
                value: values[idx]
              }));
            }
          });
        </script>
      </body>
      </html>
    `;
  };

  if (!chartData.length) {
    return (
      <View style={[styles.container, { height }]}>
        <Text style={styles.emptyText}>No data to display</Text>
      </View>
    );
  }

  return (
    <View style={[styles.container, { height }]}>
      <WebView
        ref={webViewRef}
        source={{ html: generateChartHtml() }}
        style={styles.webView}
        scrollEnabled={false}
        javaScriptEnabled={true}
        originWhitelist={['*']}
        onMessage={(event) => {
          try {
            const msg = JSON.parse(event.nativeEvent.data);
            if (DEBUG_MODE) {
              console.log('Chart interaction:', msg);
            }
          } catch (e) {
            // ignore
          }
        }}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    backgroundColor: '#fff',
    borderRadius: 12,
    overflow: 'hidden',
    marginVertical: 8,
  },
  webView: {
    flex: 1,
    backgroundColor: 'transparent',
  },
  emptyText: {
    textAlign: 'center',
    color: '#999',
    marginTop: 40,
    fontSize: 14,
  },
});

export default Chart;
