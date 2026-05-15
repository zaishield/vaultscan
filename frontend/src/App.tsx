import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { Clients } from './pages/Clients';
import { Distributors } from './pages/Distributors';
import { Resellers } from './pages/Resellers';
import { Engagements } from './pages/Engagements';
import { Scope } from './pages/Scope';
import { Assets } from './pages/Assets';
import { ExternalScans } from './pages/ExternalScans';
import { InternalAgents } from './pages/InternalAgents';
import { ScanJobs } from './pages/ScanJobs';
import { Findings } from './pages/Findings';
import { EvidenceVault } from './pages/EvidenceVault';
import { Reports } from './pages/Reports';
import { Retesting } from './pages/Retesting';
import { Remediation } from './pages/Remediation';
import { Integrations } from './pages/Integrations';
import { AuditTrail } from './pages/AuditTrail';
import { Settings } from './pages/Settings';
import { ScannerFarm } from './pages/ScannerFarm';
import { AgentOps } from './pages/AgentOps';
import { FindingClusters } from './pages/FindingClusters';
import { ChainOfCustody } from './pages/ChainOfCustody';
import { RetestBatches } from './pages/RetestBatches';
import { Compliance } from './pages/Compliance';
import { DeadLetterQueue } from './pages/DeadLetterQueue';
import { PlatformOps } from './pages/PlatformOps';
import { AuditForensics } from './pages/AuditForensics';
import { Marketplace } from './pages/Marketplace';
import { Feedback } from './pages/Feedback';
import { MobileDevices } from './pages/MobileDevices';
import { useAuthStore } from './store/auth';

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/clients" element={<Clients />} />
          <Route path="/distributors" element={<Distributors />} />
          <Route path="/resellers" element={<Resellers />} />
          <Route path="/engagements" element={<Engagements />} />
          <Route path="/scope" element={<Scope />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/scans" element={<ScanJobs />} />
          <Route path="/scans/external" element={<ExternalScans />} />
          <Route path="/agents" element={<InternalAgents />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/evidence" element={<EvidenceVault />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/retesting" element={<Retesting />} />
          <Route path="/remediation" element={<Remediation />} />
          <Route path="/integrations" element={<Integrations />} />
          <Route path="/integrations/dlq" element={<DeadLetterQueue />} />
          <Route path="/audit" element={<AuditTrail />} />
          <Route path="/audit/forensics" element={<AuditForensics />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/scanner-farm" element={<ScannerFarm />} />
          <Route path="/agents/ops" element={<AgentOps />} />
          <Route path="/findings/clusters" element={<FindingClusters />} />
          <Route path="/evidence/custody" element={<ChainOfCustody />} />
          <Route path="/retesting/batches" element={<RetestBatches />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/platform" element={<PlatformOps />} />
          <Route path="/marketplace" element={<Marketplace />} />
          <Route path="/feedback" element={<Feedback />} />
          <Route path="/mobile" element={<MobileDevices />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}

function RequireAuth() {
  const token = useAuthStore((s) => s.token);
  if (!token) return <Navigate to="/login" replace />;
  return null; // outlet provided by AppShell wrapping route
}
