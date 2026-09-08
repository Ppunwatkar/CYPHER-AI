import React, { useState } from 'react';
import { 
  Database, 
  Search, 
  FileText, 
  Sparkles, 
  ExternalLink, 
  Bot, 
  CheckCircle2, 
  Layers, 
  BookOpen,
  ArrowRight
} from 'lucide-react';
import { ScreenType } from '../../types';

interface RAGCoreScreenProps {
  onNavigate: (screen: ScreenType) => void;
  onSendToCopilot?: (query: string) => void;
}

export const RAGCoreScreen: React.FC<RAGCoreScreenProps> = ({ onNavigate, onSendToCopilot }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDoc, setSelectedDoc] = useState<string>('doc-1');

  const documents = [
    {
      id: 'doc-1',
      title: 'MITRE ATT&CK Enterprise Matrix v14.1 (Tactics & Techniques)',
      chunks: 842,
      lastIndexed: '2 hours ago',
      similarity: '0.94 Match',
      sampleSnippet: 'T1071.001 - Adversaries may communicate using standard application layer protocols (e.g., HTTP/HTTPS) to avoid detection through firewalls and proxies.'
    },
    {
      id: 'doc-2',
      title: 'Incident Handling & Containment Standard Operating Procedure (SOP-88)',
      chunks: 120,
      lastIndexed: '1 day ago',
      similarity: '0.88 Match',
      sampleSnippet: 'Upon confirmation of active C2 beaconing on tier-1 production Kubernetes nodes, analyst must sever node network interface within 45 minutes.'
    },
    {
      id: 'doc-3',
      title: 'Palo Alto PAN-OS 11.1 Dynamic Blocklist & Address Group Manual',
      chunks: 310,
      lastIndexed: '3 days ago',
      similarity: '0.81 Match',
      sampleSnippet: 'Configuration syntax for dynamic address group automation via REST API: POST /api/?type=config&action=set&xpath=/config/devices/...'
    },
    {
      id: 'doc-4',
      title: 'CVE-2024-38077 Windows Remote Desktop Licensing RCE Technical Advisory',
      chunks: 45,
      lastIndexed: '5 hours ago',
      similarity: '0.96 Match',
      sampleSnippet: 'Critical heap buffer overflow in RDL service allows unauthenticated remote code execution via malformed RPC sequence on port 135/3389.'
    }
  ];

  return (
    <div className="flex-1 flex flex-col overflow-y-auto bg-[#080b11] text-slate-100 font-mono text-xs">
      {/* Header */}
      <div className="p-6 border-b border-slate-800/80 bg-[#0a0e17]/80 space-y-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs mb-1">
            <Database className="w-4 h-4" />
            <span>SEMANTIC VECTOR KNOWLEDGE BASE & RETRIEVAL (RAG)</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            CIPHER AI — Security Knowledge Center
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Embeddings, security playbooks, vendor advisories, and MITRE ATT&CK knowledge graphs
          </p>
        </div>

        {/* Semantic Search Box */}
        <div className="relative max-w-2xl">
          <Search className="absolute left-3.5 top-3 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Test vector similarity query (e.g. 'How to isolate compromised K8s worker node?')..."
            className="w-full bg-slate-900/90 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Main Grid */}
      <div className="max-w-6xl w-full mx-auto p-6 space-y-4">
        <div className="text-slate-400 text-[11px] uppercase tracking-wider flex items-center justify-between">
          <span>Indexed Knowledge Corpus ({documents.length} Collections)</span>
          <span className="text-cyan-400">Embedding Model: text-embedding-004</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {documents.map(doc => (
            <div 
              key={doc.id}
              className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition-colors space-y-3 flex flex-col justify-between"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 font-bold">
                    {doc.similarity}
                  </span>
                  <span className="text-[10px] text-slate-500">{doc.chunks} Chunks</span>
                </div>
                <h3 className="font-bold text-slate-100 text-xs">{doc.title}</h3>
                <p className="text-slate-300 font-sans leading-relaxed text-xs p-3 rounded-lg bg-slate-950 border border-slate-800/80">
                  "{doc.sampleSnippet}"
                </p>
              </div>

              <div className="pt-2 flex items-center justify-between border-t border-slate-800/60">
                <span className="text-[10px] text-slate-500">Indexed {doc.lastIndexed}</span>
                <button
                  onClick={() => {
                    if (onSendToCopilot) {
                      onSendToCopilot(`Summarize guidance from "${doc.title}" relevant to active incidents`);
                    }
                    onNavigate('copilot');
                  }}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                >
                  <span>Query with Copilot</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
