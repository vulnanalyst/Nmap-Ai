import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import { AppLayout } from './components/layout/AppLayout';
import { OverviewPage } from './pages/OverviewPage';
import { TopologyPage } from './pages/TopologyPage';
import { ScansPage } from './pages/ScansPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { AlertsPage } from './pages/AlertsPage';
import { TrafficPage } from './pages/TrafficPage';
import { MLLabPage } from './pages/MLLabPage';
import { RiskEnginePage } from './pages/RiskEnginePage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

function App() {
  return (
    <AppProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AppLayout />}>
            <Route index element={<OverviewPage />} />
            <Route path="topology" element={<TopologyPage />} />
            <Route path="scans" element={<ScansPage />} />
            <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="traffic" element={<TrafficPage />} />
            <Route path="ml" element={<MLLabPage />} />
            <Route path="risk" element={<RiskEnginePage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AppProvider>
  );
}

export default App;
