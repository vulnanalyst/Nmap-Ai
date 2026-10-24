import React, { useEffect, useState, useCallback } from 'react';
import {
  Cpu,
  BarChart2,
  Play,
  RotateCw,
  Sliders,
  Info,
  Sparkles,
  History,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { MLModelResponse, TrainingRunItem } from '../types';

const DEFAULT_FEATURES: Record<string, number> = {
  'Destination Port': 445,
  'Flow Duration': 120500,
  'Total Fwd Packets': 15,
  'Total Backward Packets': 12,
  'Total Length of Fwd Packets': 960,
  'Fwd Packet Length Max': 128,
  'Bwd Packet Length Max': 128,
  'Flow Bytes/s': 24500,
  'Flow Packets/s': 420.5,
  'Average Packet Size': 74.2,
};

export const MLLabPage: React.FC = () => {
  const { showToast } = useApp();
  const [modelData, setModelData] = useState<MLModelResponse | null>(null);
  const [trainingRuns, setTrainingRuns] = useState<TrainingRunItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Playground state
  const [features, setFeatures] = useState<Record<string, number>>(DEFAULT_FEATURES);
  const [inferenceResult, setInferenceResult] = useState<{
    prediction: number;
    label: string;
    probability: number;
    model_version: string;
    class_probabilities: Record<string, number>;
  } | null>(null);
  const [inferring, setInferring] = useState<boolean>(false);

  // Retraining state
  const [training, setTraining] = useState<boolean>(false);

  const fetchModelData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [modelRes, runsRes] = await Promise.all([
        api.getModelInfo(),
        api.getTrainingRuns(),
      ]);
      setModelData(modelRes);
      setTrainingRuns(runsRes.items);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch ML model details');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchModelData();
  }, [fetchModelData]);

  // Run Playground Inference
  const handleInfer = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setInferring(true);
      const res = await api.inferFeatures(features);
      setInferenceResult(res);
      showToast(`Model Inference: Classified as ${res.label} (${(res.probability * 100).toFixed(1)}%)`, 'info');
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Inference failed', 'error');
    } finally {
      setInferring(false);
    }
  };

  // Trigger Retraining
  const handleTriggerTraining = async () => {
    try {
      setTraining(true);
      const run = await api.startTraining();
      showToast(`Training run started [ID: ${run.id.slice(0, 8)}]`, 'info');
      // Poll until finished
      const poll = setInterval(async () => {
        try {
          const runs = await api.getTrainingRuns();
          setTrainingRuns(runs.items);
          const active = runs.items.find((r) => r.id === run.id);
          if (active && (active.status === 'completed' || active.status === 'error')) {
            clearInterval(poll);
            setTraining(false);
            if (active.status === 'completed') {
              showToast('Model training completed and new version activated!', 'success');
              fetchModelData();
            } else {
              showToast(`Training failed: ${active.error}`, 'error');
            }
          }
        } catch {
          clearInterval(poll);
          setTraining(false);
        }
      }, 3000);
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to start training', 'error');
      setTraining(false);
    }
  };

  const activeModel = modelData?.active;
  const metrics = activeModel?.metrics?.random_forest;
  const featureImportance = activeModel?.metrics?.feature_importance || [];
  const confusionMatrix = metrics?.confusion_matrix || [
    [0, 0],
    [0, 0],
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100">AI / ML Lab — Training & Evaluation</h1>
            <span className="px-2 py-0.5 rounded text-xs font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
              REAL SCIKIT-LEARN ENGINE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Reproducible network flow classification. Model artifacts, schema definitions, and confusion matrices derived from real evaluation splits.
          </p>
        </div>

        <button
          onClick={handleTriggerTraining}
          disabled={training}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-900 text-xs font-semibold rounded-md flex items-center gap-2 transition-colors shadow-lg shadow-cyan-950/50 self-start"
        >
          <RotateCw className={`w-3.5 h-3.5 ${training ? 'animate-spin' : ''}`} />
          <span>{training ? 'Retraining Baseline...' : 'Retrain Random Forest'}</span>
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchModelData} />}

      {/* Benchmark Disclaimer Alert */}
      <div className="bg-slate-900/80 border border-cyan-900/60 rounded-lg p-3.5 text-xs flex items-start gap-3">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-slate-300">
          <span className="font-semibold text-cyan-300">Academic & Lab Transparency Disclaimer: </span>
          <span>{modelData?.disclaimer || 'Offline CIC-IDS2017 evaluation does not guarantee accuracy on live lab traffic. Anomaly scores are probabilistic hints, never definitive proof of compromise.'}</span>
        </div>
      </div>

      {/* Model Overview Card */}
      {loading && !activeModel ? (
        <LoadingSkeleton rows={4} />
      ) : activeModel ? (
        <Card
          title={`Active Model: ${activeModel.version}`}
          subtitle={`Algorithm: ${activeModel.model_type} (${activeModel.algorithm}) &bull; Trained: ${new Date(activeModel.trained_at).toLocaleString()}`}
          icon={<Cpu className="w-4 h-4" />}
        >
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-3 bg-slate-900 rounded border border-slate-800">
              <span className="text-slate-400 text-[11px] block">Macro F1 Score</span>
              <span className="text-xl font-bold text-emerald-400 mt-1 block">
                {metrics ? (metrics.f1_macro * 100).toFixed(2) : '—'}%
              </span>
            </div>
            <div className="p-3 bg-slate-900 rounded border border-slate-800">
              <span className="text-slate-400 text-[11px] block">Balanced Accuracy</span>
              <span className="text-xl font-bold text-cyan-300 mt-1 block">
                {metrics ? (metrics.balanced_accuracy * 100).toFixed(2) : '—'}%
              </span>
            </div>
            <div className="p-3 bg-slate-900 rounded border border-slate-800">
              <span className="text-slate-400 text-[11px] block">Macro Precision</span>
              <span className="text-xl font-bold text-slate-100 mt-1 block">
                {metrics ? (metrics.precision_macro * 100).toFixed(2) : '—'}%
              </span>
            </div>
            <div className="p-3 bg-slate-900 rounded border border-slate-800">
              <span className="text-slate-400 text-[11px] block">Macro Recall</span>
              <span className="text-xl font-bold text-slate-100 mt-1 block">
                {metrics ? (metrics.recall_macro * 100).toFixed(2) : '—'}%
              </span>
            </div>
          </div>
        </Card>
      ) : (
        <EmptyState
          icon={<Cpu className="w-8 h-8 text-cyan-400" />}
          title="No Model Artifacts Saved"
          description="Click 'Retrain Random Forest' above to train the baseline model on dataset/final_dataset.csv."
        />
      )}

      {/* Metrics Row: Feature Importance & Confusion Matrix */}
      {metrics && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Feature Importance Chart */}
          <Card
            title="Flow Feature Importance Ranking"
            subtitle="Gini impurity reduction across Random Forest decision trees"
            icon={<BarChart2 className="w-4 h-4" />}
          >
            <div className="h-72 w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={featureImportance}
                  layout="vertical"
                  margin={{ top: 5, right: 30, left: 120, bottom: 5 }}
                >
                  <XAxis type="number" stroke="#64748b" fontSize={10} domain={[0, 'dataMax + 0.05']} />
                  <YAxis
                    dataKey="feature"
                    type="category"
                    stroke="#94a3b8"
                    fontSize={10}
                    tick={{ fill: '#cbd5e1' }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '6px',
                      fontSize: '12px',
                    }}
                    formatter={(val: any) => [`${(Number(val) * 100).toFixed(2)}%`, 'Weight']}
                  />
                  <Bar dataKey="importance" fill="#06b6d4" radius={[0, 4, 4, 0]}>
                    {featureImportance.map((_, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={index < 3 ? '#06b6d4' : index < 6 ? '#0ea5e9' : '#475569'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>

          {/* Confusion Matrix & Classification Report */}
          <Card
            title="Confusion Matrix & Per-Class Evaluation"
            subtitle="Verified test partition (400 stratified samples)"
            icon={<Sliders className="w-4 h-4" />}
          >
            <div className="space-y-4 text-xs">
              {/* 2x2 Matrix */}
              <div>
                <span className="text-slate-400 font-semibold block mb-2 uppercase text-[11px]">
                  Confusion Matrix (Test Set)
                </span>
                <div className="grid grid-cols-2 gap-2 text-center font-mono">
                  <div className="p-3 bg-emerald-950/40 border border-emerald-900 rounded">
                    <span className="text-[10px] text-emerald-400 block">True BENIGN (TN)</span>
                    <span className="text-lg font-bold text-emerald-300">{confusionMatrix[0]?.[0] ?? 0}</span>
                  </div>
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded">
                    <span className="text-[10px] text-slate-400 block">False ATTACK (FP)</span>
                    <span className="text-lg font-bold text-slate-300">{confusionMatrix[0]?.[1] ?? 0}</span>
                  </div>
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded">
                    <span className="text-[10px] text-slate-400 block">False BENIGN (FN)</span>
                    <span className="text-lg font-bold text-slate-300">{confusionMatrix[1]?.[0] ?? 0}</span>
                  </div>
                  <div className="p-3 bg-red-950/40 border border-red-900 rounded">
                    <span className="text-[10px] text-red-400 block">True ATTACK (TP)</span>
                    <span className="text-lg font-bold text-red-300">{confusionMatrix[1]?.[1] ?? 0}</span>
                  </div>
                </div>
              </div>

              {/* Per-Class Report */}
              <div>
                <span className="text-slate-400 font-semibold block mb-2 uppercase text-[11px]">
                  Classification Report
                </span>
                <div className="border border-slate-800 rounded overflow-hidden">
                  <table className="w-full text-left text-[11px] font-mono">
                    <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-2">Class</th>
                        <th className="p-2">Precision</th>
                        <th className="p-2">Recall</th>
                        <th className="p-2">F1-Score</th>
                        <th className="p-2">Support</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {metrics.classification_report &&
                        Object.entries(metrics.classification_report)
                          .filter(([k]) => k === '0' || k === '1')
                          .map(([clsKey, cMetrics]) => (
                            <tr key={clsKey} className="hover:bg-slate-900/50">
                              <td className="p-2 font-semibold text-slate-200">
                                {clsKey === '0' ? 'BENIGN (0)' : 'ATTACK (1)'}
                              </td>
                              <td className="p-2 text-slate-300">{(cMetrics.precision * 100).toFixed(1)}%</td>
                              <td className="p-2 text-slate-300">{(cMetrics.recall * 100).toFixed(1)}%</td>
                              <td className="p-2 text-slate-300">{(cMetrics['f1-score'] * 100).toFixed(1)}%</td>
                              <td className="p-2 text-slate-400">{cMetrics.support}</td>
                            </tr>
                          ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Model Inference Playground */}
      <Card
        title="Live Model Inference Playground"
        subtitle="Test exact 10-feature flow vectors against the loaded model with probability calibration"
        icon={<Sparkles className="w-4 h-4" />}
      >
        <form onSubmit={handleInfer} className="space-y-4 text-xs">
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {Object.keys(DEFAULT_FEATURES).map((featName) => (
              <div key={featName}>
                <label className="block text-slate-400 text-[11px] truncate mb-1" title={featName}>
                  {featName}
                </label>
                <input
                  type="number"
                  step="any"
                  value={features[featName] ?? 0}
                  onChange={(e) =>
                    setFeatures({
                      ...features,
                      [featName]: parseFloat(e.target.value) || 0,
                    })
                  }
                  className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-slate-100 font-mono text-xs focus:outline-hidden focus:border-cyan-500"
                />
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setFeatures(DEFAULT_FEATURES)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Reset to Defaults
            </button>

            <button
              type="submit"
              disabled={inferring}
              className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-900 font-semibold rounded text-xs transition-colors flex items-center gap-1.5 shadow-md shadow-cyan-950/50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{inferring ? 'Running Inference...' : 'Evaluate Vector'}</span>
            </button>
          </div>

          {/* Inference Output */}
          {inferenceResult && (
            <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 space-y-2 font-mono">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-xs">Model Prediction:</span>
                <span
                  className={`text-sm font-bold px-2 py-0.5 rounded uppercase ${
                    inferenceResult.label === 'ATTACK'
                      ? 'bg-red-950 text-red-400 border border-red-800'
                      : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  }`}
                >
                  {inferenceResult.label} ({inferenceResult.prediction})
                </span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Class Probability:</span>
                <span className="text-cyan-300 font-semibold">
                  {(inferenceResult.probability * 100).toFixed(2)}%
                </span>
              </div>
              <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800">
                Model version: {inferenceResult.model_version} &bull; Output calibrated against explicit class ordering [BENIGN, ATTACK].
              </div>
            </div>
          )}
        </form>
      </Card>

      {/* Training Runs History */}
      {trainingRuns.length > 0 && (
        <Card
          title={`Training Run History (${trainingRuns.length})`}
          subtitle="Audit log of background scikit-learn training jobs"
          icon={<History className="w-4 h-4" />}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Run ID</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Model Version</th>
                  <th className="py-2.5 px-3">Started At</th>
                  <th className="py-2.5 px-3">Finished At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {trainingRuns.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-900/40">
                    <td className="py-2.5 px-3 text-cyan-300">{r.id.slice(0, 8)}...</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          r.status === 'completed'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : r.status === 'running'
                            ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 animate-pulse'
                            : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        {r.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">{r.model_version || '—'}</td>
                    <td className="py-2.5 px-3 text-slate-400">{r.started_at ? new Date(r.started_at).toLocaleTimeString() : '—'}</td>
                    <td className="py-2.5 px-3 text-slate-400">{r.finished_at ? new Date(r.finished_at).toLocaleTimeString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
};
