import React, { useState, useRef } from 'react';
import axios from 'axios';
import { UploadCloud, CheckCircle, AlertTriangle } from 'lucide-react';

const UploadView: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [action, setAction] = useState('extract');
  const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
      setStatus('idle');
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setStatus('uploading');
    setMessage('');
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('action', action);

    try {
      const token = localStorage.getItem('token');
      const res = await axios.post('http://localhost:8000/api/upload', formData, {
        headers: { 
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${token}` 
        }
      });
      
      setStatus('success');
      if (action === 'review') {
        setMessage(res.data.recommendations || 'Review complete.');
      } else {
        setMessage(res.data.message || 'File uploaded successfully.');
      }
    } catch (err: unknown) {
      setStatus('error');
      const detail = axios.isAxiosError<{ detail?: string }>(err)
        ? err.response?.data?.detail
        : undefined;
      setMessage(detail || 'Failed to upload file.');
    }
  };

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <h2 className="gradient-text">Upload Documents</h2>
      <p style={{ color: 'var(--text-secondary)' }}>Upload your incident reports, frameworks, or policies here.</p>

      <div 
        className="glass-panel"
        style={{
          border: '2px dashed var(--border-color)',
          padding: '48px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '16px',
          cursor: 'pointer',
          transition: 'border-color 0.3s ease',
          backgroundColor: file ? 'rgba(59, 130, 246, 0.05)' : 'var(--bg-surface)'
        }}
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <UploadCloud size={48} color={file ? 'var(--accent-primary)' : 'var(--text-secondary)'} />
        {file ? (
          <div style={{ textAlign: 'center' }}>
            <h3 style={{ color: 'var(--text-primary)' }}>{file.name}</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>{(file.size / 1024).toFixed(2)} KB</p>
          </div>
        ) : (
          <div style={{ textAlign: 'center' }}>
            <h3 style={{ color: 'var(--text-primary)' }}>Drag & drop your file here</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>or click to browse (PDF, DOCX, TXT)</p>
          </div>
        )}
        <input 
          type="file" 
          ref={fileInputRef} 
          style={{ display: 'none' }} 
          accept=".pdf,.docx,.txt,.md"
          onChange={(e) => {
            if (e.target.files && e.target.files.length > 0) {
              setFile(e.target.files[0]);
              setStatus('idle');
            }
          }}
        />
      </div>

      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-secondary)' }}>Action to Perform</label>
          <select 
            className="glass-input" 
            value={action} 
            onChange={(e) => setAction(e.target.value)}
            style={{ width: '100%', cursor: 'pointer' }}
          >
            <option value="extract" style={{ color: 'black' }}>Extract IoCs (Add to KB)</option>
            <option value="review" style={{ color: 'black' }}>Review Governance Framework</option>
          </select>
        </div>

        <button 
          className="btn btn-primary" 
          onClick={handleUpload} 
          disabled={!file || status === 'uploading'}
          style={{ width: '100%', padding: '12px' }}
        >
          {status === 'uploading' ? 'Processing...' : 'Upload & Process'}
        </button>
      </div>

      {status === 'success' && (
        <div className="glass-panel" style={{ padding: '24px', borderColor: 'var(--success)', display: 'flex', gap: '16px' }}>
          <CheckCircle color="var(--success)" style={{ flexShrink: 0 }} />
          <div>
            <h4 style={{ color: 'var(--success)', marginBottom: '8px' }}>Success</h4>
            <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              {message}
            </pre>
          </div>
        </div>
      )}

      {status === 'error' && (
        <div className="glass-panel" style={{ padding: '24px', borderColor: 'var(--danger)', display: 'flex', gap: '16px' }}>
          <AlertTriangle color="var(--danger)" style={{ flexShrink: 0 }} />
          <div>
            <h4 style={{ color: 'var(--danger)', marginBottom: '8px' }}>Error</h4>
            <p style={{ color: 'var(--text-secondary)' }}>{message}</p>
          </div>
        </div>
      )}

    </div>
  );
};

export default UploadView;
