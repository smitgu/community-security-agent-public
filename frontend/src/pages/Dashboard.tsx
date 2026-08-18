import React from 'react';
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import { MessageSquare, Network, FileText, LogOut, ShieldAlert, Globe } from 'lucide-react';
import Chat from '../components/Chat';
import GraphView from '../components/GraphView';
import UploadView from '../components/UploadView';
import DiscourseView from '../components/DiscourseView';

interface DashboardProps {
  onLogout: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ onLogout }) => {
  const navigate = useNavigate();
  const location = useLocation();

  const navItems = [
    { path: '/dashboard', label: 'Chat & Query', icon: <MessageSquare size={20} /> },
    { path: '/dashboard/graph', label: 'Provenance Graph', icon: <Network size={20} /> },
    { path: '/dashboard/upload', label: 'Upload Documents', icon: <FileText size={20} /> },
    { path: '/dashboard/discourse', label: 'Discourse Sync', icon: <Globe size={20} /> },
  ];

  return (
    <div className="app-container">
      <aside className="sidebar glass-panel" style={{ borderRadius: 0, borderTop: 0, borderBottom: 0, borderLeft: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', paddingBottom: '24px', borderBottom: '1px solid var(--border-color)' }}>
          <ShieldAlert size={32} color="var(--accent-primary)" />
          <h2 className="gradient-text">Community Security Agent</h2>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1 }}>
          {navItems.map((item) => (
            <button
              key={item.path}
              onClick={() => navigate(item.path)}
              className={`btn ${location.pathname === item.path ? 'btn-primary' : 'btn-secondary'}`}
              style={{ justifyContent: 'flex-start', width: '100%', border: 'none', background: location.pathname === item.path ? '' : 'transparent' }}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>

        <button onClick={onLogout} className="btn btn-secondary" style={{ marginTop: 'auto', border: 'none', background: 'rgba(239, 68, 68, 0.1)', color: 'var(--danger)' }}>
          <LogOut size={20} />
          Logout
        </button>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <h3 style={{ color: 'var(--text-secondary)' }}>
            {navItems.find(i => i.path === location.pathname)?.label || 'Dashboard'}
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: 'var(--accent-gradient)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold' }}>
              A
            </div>
            <span>Admin</span>
          </div>
        </header>
        
        <div className="content-area">
          <Routes>
            <Route path="/" element={<Chat />} />
            <Route path="/graph" element={<GraphView />} />
            <Route path="/upload" element={<UploadView />} />
            <Route path="/discourse" element={<DiscourseView />} />
          </Routes>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
