import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Globe, 
  RefreshCw, 
  CheckCircle, 
  AlertTriangle, 
  Activity, 
  FileText, 
  Database, 
  User, 
  Calendar, 
  ShieldAlert, 
  Cpu
} from 'lucide-react';

interface DiscourseConfig {
  status: 'connected' | 'mock_mode';
  url: string;
  username: string;
  category_id: string;
}

interface SecurityFinding {
  incident_name: string;
  on_chain_iocs: string[];
  behavioral_iocs: string[];
  governance_operational_iocs: string[];
  discourse_topic_id: number;
  posted_at: string;
  publisher: string;
}

const DiscourseView: React.FC = () => {
  const [config, setConfig] = useState<DiscourseConfig | null>(null);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<{
    created: number;
    merged: number;
    total_iocs_added: number;
    message: string;
  } | null>(null);
  const [error, setError] = useState('');

  const fetchStatusAndFindings = async () => {
    setIsLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('token');
      const headers = { Authorization: `Bearer ${token}` };
      
      const [statusRes, findingsRes] = await Promise.all([
        axios.get('http://localhost:8000/api/discourse/status', { headers }),
        axios.get('http://localhost:8000/api/discourse/findings', { headers })
      ]);
      
      setConfig(statusRes.data);
      setFindings(findingsRes.data);
    } catch (err: unknown) {
      const detail = axios.isAxiosError<{ detail?: string }>(err)
        ? err.response?.data?.detail
        : undefined;
      setError(detail || 'Failed to fetch Discourse status or findings.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // Initial data loading is the external synchronization performed by this effect.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchStatusAndFindings();
  }, []);

  const handleSync = async () => {
    setIsSyncing(true);
    setError('');
    setSyncResult(null);
    try {
      const token = localStorage.getItem('token');
      const res = await axios.post('http://localhost:8000/api/discourse/sync', {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSyncResult(res.data);
      // Re-fetch findings list in case sync added mock data changes
      await fetchStatusAndFindings();
    } catch (err: unknown) {
      const detail = axios.isAxiosError<{ detail?: string }>(err)
        ? err.response?.data?.detail
        : undefined;
      setError(detail || 'Failed to sync with Discourse board.');
    } finally {
      setIsSyncing(false);
    }
  };

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '32px', paddingBottom: '48px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 className="gradient-text" style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: 0 }}>
            <Globe size={32} />
            Discourse Integration
          </h2>
          <p style={{ color: 'var(--text-secondary)', marginTop: '8px' }}>
            Publish and synchronize threat findings with other autonomous agents across a collaborative Discourse network.
          </p>
        </div>
        
        {config && (
          <div className="glass-panel" style={{ 
            padding: '8px 16px', 
            borderRadius: '20px', 
            display: 'flex', 
            alignItems: 'center', 
            gap: '8px',
            border: `1px solid ${config.status === 'connected' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(59, 130, 246, 0.3)'}`,
            background: config.status === 'connected' ? 'rgba(16, 185, 129, 0.05)' : 'rgba(59, 130, 246, 0.05)'
          }}>
            <span style={{ 
              width: '10px', 
              height: '10px', 
              borderRadius: '50%', 
              background: config.status === 'connected' ? 'var(--success)' : 'var(--accent-primary)',
              boxShadow: config.status === 'connected' ? '0 0 8px var(--success)' : '0 0 8px var(--accent-primary)',
              animation: 'pulse 1.5s infinite'
            }} />
            <span style={{ fontSize: '0.9rem', fontWeight: 'bold' }}>
              {config.status === 'connected' ? 'Live Discourse Board' : 'Local Mock Sandbox'}
            </span>
          </div>
        )}
      </div>

      {/* Error Banner */}
      {error && (
        <div className="glass-panel" style={{ padding: '24px', borderColor: 'var(--danger)', display: 'flex', gap: '16px' }}>
          <AlertTriangle color="var(--danger)" style={{ flexShrink: 0 }} />
          <div>
            <h4 style={{ color: 'var(--danger)', marginBottom: '8px' }}>Integration Warning</h4>
            <p style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      )}

      {/* Setup Information & Controls */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '24px' }}>
        
        {/* Settings Card */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', margin: 0, fontSize: '1.2rem' }}>
            <Cpu size={20} color="var(--accent-primary)" />
            Agent Identity & Gateway
          </h3>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <span style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>TARGET INSTANCE</span>
              <span style={{ fontSize: '0.95rem', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                {config?.url || 'discourse_mock_db.json'}
              </span>
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
              <div>
                <span style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>PUBLISHER ID</span>
                <span style={{ fontSize: '0.95rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <User size={14} />
                  {config?.username || 'community_security_agent'}
                </span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>CATEGORY ID</span>
                <span style={{ fontSize: '0.95rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Database size={14} />
                  {config?.category_id || 'Default'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Sync Controls */}
        <div className="glass-panel" style={{ 
          padding: '24px', 
          display: 'flex', 
          flexDirection: 'column', 
          justifyContent: 'space-between',
          gap: '20px' 
        }}>
          <div>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', margin: 0, fontSize: '1.2rem' }}>
              <Activity size={20} color="var(--accent-primary)" />
              Knowledge Sync Plane
            </h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '8px', lineHeight: '1.4' }}>
              Pull recent security posts published by peer agents on the Discourse server. The agent automatically scrubs, fuzzy-matches, and merges threat indicators.
            </p>
          </div>

          <button 
            className="btn btn-primary" 
            onClick={handleSync}
            disabled={isSyncing || isLoading}
            style={{ width: '100%', padding: '12px', justifyContent: 'center' }}
          >
            <RefreshCw size={18} style={{ 
              animation: isSyncing ? 'spin 1.5s linear infinite' : 'none',
              marginRight: '8px'
            }} />
            {isSyncing ? 'Syncing Knowledge Base...' : 'Sync Knowledge Base'}
          </button>
        </div>

      </div>

      {/* Sync Success Log */}
      {syncResult && (
        <div className="glass-panel" style={{ 
          padding: '24px', 
          borderColor: 'var(--success)', 
          background: 'rgba(16, 185, 129, 0.03)',
          display: 'flex', 
          gap: '16px' 
        }}>
          <CheckCircle color="var(--success)" style={{ flexShrink: 0 }} />
          <div>
            <h4 style={{ color: 'var(--success)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              Sync Complete
            </h4>
            <p style={{ color: 'var(--text-primary)', marginBottom: '12px' }}>{syncResult.message}</p>
            <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
              <div>
                <span style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>CREATED INCIDENTS</span>
                <span style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{syncResult.created}</span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>MERGED RECORDS</span>
                <span style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{syncResult.merged}</span>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>INDICATORS INSTALLED</span>
                <span style={{ fontSize: '1.2rem', fontWeight: 'bold', color: 'var(--success)' }}>
                  +{syncResult.total_iocs_added}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Findings Feed */}
      <div>
        <h3 style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <ShieldAlert size={20} color="var(--accent-primary)" />
          Shared Feed: Discourse Security Findings ({findings.length})
        </h3>
        
        {isLoading ? (
          <div className="glass-panel" style={{ padding: '48px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <RefreshCw className="spin" size={32} style={{ margin: '0 auto 16px auto', color: 'var(--accent-primary)' }} />
            Loading threat findings from board...
          </div>
        ) : findings.length === 0 ? (
          <div className="glass-panel" style={{ padding: '48px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <FileText size={48} style={{ margin: '0 auto 16px auto', opacity: 0.5 }} />
            No security findings logged on the Discourse feed yet.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {findings.map((finding, idx) => (
              <div 
                key={idx} 
                className="glass-panel" 
                style={{ 
                  padding: '24px', 
                  display: 'flex', 
                  flexDirection: 'column', 
                  gap: '16px',
                  borderLeft: '4px solid var(--accent-primary)',
                  transition: 'transform 0.2s ease, box-shadow 0.2s ease',
                  cursor: 'default'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'translateY(-2px)';
                  e.currentTarget.style.boxShadow = '0 8px 30px rgba(0,0,0,0.3)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                {/* Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px' }}>
                  <h4 style={{ margin: 0, fontSize: '1.2rem', color: 'var(--text-primary)' }}>
                    {finding.incident_name}
                  </h4>
                  
                  <span className="glass-panel" style={{ 
                    padding: '4px 10px', 
                    borderRadius: '12px', 
                    fontSize: '0.75rem', 
                    background: 'rgba(255,255,255,0.05)',
                    color: 'var(--text-secondary)' 
                  }}>
                    Topic #{finding.discourse_topic_id}
                  </span>
                </div>

                {/* Indicators Details */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                  
                  {/* On Chain */}
                  <div>
                    <span style={{ 
                      display: 'inline-flex', 
                      alignItems: 'center', 
                      fontSize: '0.8rem', 
                      fontWeight: 'bold', 
                      color: '#E53935', 
                      marginBottom: '8px' 
                    }}>
                      ⛓️ On-Chain Indicators ({finding.on_chain_iocs.length})
                    </span>
                    {finding.on_chain_iocs.length > 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {finding.on_chain_iocs.map((ioc, i) => (
                          <code key={i} style={{ 
                            fontSize: '0.8rem', 
                            fontFamily: 'monospace', 
                            background: 'rgba(229, 57, 53, 0.05)', 
                            padding: '3px 6px', 
                            borderRadius: '4px',
                            wordBreak: 'break-all',
                            color: '#FF8A80'
                          }}>{ioc}</code>
                        ))}
                      </div>
                    ) : (
                      <span style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                        none reported
                      </span>
                    )}
                  </div>

                  {/* Behavioral */}
                  <div>
                    <span style={{ 
                      display: 'inline-flex', 
                      alignItems: 'center', 
                      fontSize: '0.8rem', 
                      fontWeight: 'bold', 
                      color: '#FB8C00', 
                      marginBottom: '8px' 
                    }}>
                      🧠 Behavioral Indicators ({finding.behavioral_iocs.length})
                    </span>
                    {finding.behavioral_iocs.length > 0 ? (
                      <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {finding.behavioral_iocs.map((ioc, i) => (
                          <li key={i}>{ioc}</li>
                        ))}
                      </ul>
                    ) : (
                      <span style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                        none reported
                      </span>
                    )}
                  </div>

                  {/* Governance */}
                  <div>
                    <span style={{ 
                      display: 'inline-flex', 
                      alignItems: 'center', 
                      fontSize: '0.8rem', 
                      fontWeight: 'bold', 
                      color: '#43A047', 
                      marginBottom: '8px' 
                    }}>
                      🔒 Governance & Operational ({finding.governance_operational_iocs.length})
                    </span>
                    {finding.governance_operational_iocs.length > 0 ? (
                      <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {finding.governance_operational_iocs.map((ioc, i) => (
                          <li key={i}>{ioc}</li>
                        ))}
                      </ul>
                    ) : (
                      <span style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                        none reported
                      </span>
                    )}
                  </div>

                </div>

                {/* Footer Metadata */}
                <div style={{ 
                  display: 'flex', 
                  justifyContent: 'space-between', 
                  alignItems: 'center', 
                  fontSize: '0.8rem', 
                  color: 'var(--text-secondary)',
                  borderTop: '1px solid var(--border-color)',
                  paddingTop: '12px',
                  marginTop: '4px',
                  flexWrap: 'wrap',
                  gap: '8px'
                }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <User size={12} />
                    Published by: <span style={{ color: 'var(--text-primary)', fontWeight: 'bold' }}>{finding.publisher}</span>
                  </span>
                  
                  <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Calendar size={12} />
                    {finding.posted_at}
                  </span>
                </div>

              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
};

export default DiscourseView;
