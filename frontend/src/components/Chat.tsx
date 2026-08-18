import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import { Send, Bot, User } from 'lucide-react';

interface Message {
  id: string;
  sender: 'user' | 'agent';
  text: string;
}

const Chat: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    { id: '1', sender: 'agent', text: 'Hello! I am the Community Security Agent. You can ask me to extract IoCs, show top incidents, or provide a report.' }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMsg: Message = { id: Date.now().toString(), sender: 'user', text: input };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const token = localStorage.getItem('token');
      const res = await axios.post('http://localhost:8000/api/chat', { message: userMsg.text }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      const agentMsg: Message = {
        id: (Date.now() + 1).toString(),
        sender: 'agent',
        text: res.data.message || JSON.stringify(res.data, null, 2),
      };
      setMessages(prev => [...prev, agentMsg]);
    } catch {
      setMessages(prev => [...prev, { id: Date.now().toString(), sender: 'agent', text: 'Error communicating with backend.' }]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="glass-panel chat-container" style={{ height: '100%', padding: '24px' }}>
      <div className="chat-messages">
        {messages.map(msg => (
          <div key={msg.id} className={`message ${msg.sender}`} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
            <div style={{ padding: '8px', borderRadius: '50%', background: msg.sender === 'user' ? 'rgba(255,255,255,0.2)' : 'var(--accent-gradient)' }}>
              {msg.sender === 'user' ? <User size={20} color="white" /> : <Bot size={20} color="white" />}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.8rem', color: msg.sender === 'user' ? 'rgba(255,255,255,0.7)' : 'var(--text-secondary)', marginBottom: '4px' }}>
                {msg.sender === 'user' ? 'You' : 'Security Agent'}
              </div>
              <div style={{ whiteSpace: 'pre-wrap' }}>{msg.text}</div>
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="message agent" style={{ animation: 'pulse 1s infinite' }}>
            Thinking...
          </div>
        )}
        <div ref={endRef} />
      </div>
      
      <div className="chat-input-area" style={{ display: 'flex', gap: '12px' }}>
        <input 
          type="text" 
          className="glass-input" 
          value={input} 
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSend()}
          placeholder="Type your message or ask to analyze IoCs..."
          style={{ flex: 1 }}
        />
        <button className="btn btn-primary" onClick={handleSend} disabled={isLoading || !input.trim()}>
          <Send size={20} />
        </button>
      </div>
    </div>
  );
};

export default Chat;
