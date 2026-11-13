import { useState, useEffect } from 'react'
import './App.css'

interface FlowLogEntry {
  version: number
  account_id: string
  interface_id: string
  src_addr: string
  dst_addr: string
  src_port: number
  dst_port: number
  protocol: number
  packets: number
  bytes: number
  start_time: number
  end_time: number
  action: string
  log_status: string
}

interface DetectionResult {
  rule_id: string
  rule_name: string
  severity: string
  timestamp: string
  flow_log: FlowLogEntry
  details: string
}

interface SecurityGroupRule {
  ip_protocol: string
  from_port: number
  to_port: number
  cidr_ipv4?: string
  cidr_ipv6?: string
  referenced_group_id?: string
  description?: string
}

interface SecurityGroup {
  group_id: string
  group_name: string
  description: string
  vpc_id: string
  rules: SecurityGroupRule[]
}

interface AuditFinding {
  id: string
  severity: string
  title: string
  description: string
  resource_id: string
  resource_type: string
  remediation: string
  timestamp: string
}

interface DetectionRule {
  id: string
  name: string
  severity: string
  enabled: boolean
}

interface AuditRule {
  id: string
  name: string
  severity: string
  enabled: boolean
}

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

function App() {
  const [activeTab, setActiveTab] = useState<'detection' | 'ingestion' | 'security-audit'>('detection')
  const [flowLogs, setFlowLogs] = useState<FlowLogEntry[]>([])
  const [detectionResults, setDetectionResults] = useState<DetectionResult[]>([])
  const [detectionRules, setDetectionRules] = useState<DetectionRule[]>([])
  const [securityGroups] = useState<SecurityGroup[]>([])
  const [auditFindings, setAuditFindings] = useState<AuditFinding[]>([])
  const [auditRules, setAuditRules] = useState<AuditRule[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [newFlowLog, setNewFlowLog] = useState<Partial<FlowLogEntry>>({
    version: 2,
    account_id: '',
    interface_id: '',
    src_addr: '',
    dst_addr: '',
    src_port: 0,
    dst_port: 0,
    protocol: 6,
    packets: 0,
    bytes: 0,
    start_time: Math.floor(Date.now() / 1000),
    end_time: Math.floor(Date.now() / 1000),
    action: 'ACCEPT',
    log_status: 'OK'
  })

  useEffect(() => {
    fetchDetectionRules()
    fetchAuditRules()
  }, [])

  async function fetchDetectionRules() {
    try {
      const res = await fetch(`${API_BASE}/api/v1/detection/rules`)
      const data = await res.json()
      setDetectionRules(data.rules)
    } catch (e) {
      console.error('Failed to fetch detection rules', e)
    }
  }

  async function fetchAuditRules() {
    try {
      const res = await fetch(`${API_BASE}/api/v1/security-audit/rules`)
      const data = await res.json()
      setAuditRules(data.rules)
    } catch (e) {
      console.error('Failed to fetch audit rules', e)
    }
  }

  async function analyzeFlowLogs() {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API_BASE}/api/v1/detection/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(flowLogs.length > 0 ? flowLogs : [newFlowLog])
      })
      if (!res.ok) throw new Error('Analysis failed')
      const data = await res.json()
      setDetectionResults(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  async function analyzeSecurityGroups() {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API_BASE}/api/v1/security-audit/security-groups/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(securityGroups.length > 0 ? securityGroups : [{
          group_id: 'sg-12345',
          group_name: 'test-sg',
          description: 'Test security group',
          vpc_id: 'vpc-12345',
          rules: [{
            ip_protocol: 'tcp',
            from_port: 22,
            to_port: 22,
            cidr_ipv4: '0.0.0.0/0',
            description: 'SSH from anywhere'
          }]
        }])
      })
      if (!res.ok) throw new Error('Audit failed')
      const data = await res.json()
      setAuditFindings(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Audit failed')
    } finally {
      setLoading(false)
    }
  }

  function handleFlowLogChange(field: string, value: string | number) {
    setNewFlowLog(prev => ({ ...prev, [field]: value }))
  }

  function addFlowLog() {
    setFlowLogs(prev => [...prev, newFlowLog as FlowLogEntry])
    setNewFlowLog({
      version: 2,
      account_id: '',
      interface_id: '',
      src_addr: '',
      dst_addr: '',
      src_port: 0,
      dst_port: 0,
      protocol: 6,
      packets: 0,
      bytes: 0,
      start_time: Math.floor(Date.now() / 1000),
      end_time: Math.floor(Date.now() / 1000),
      action: 'ACCEPT',
      log_status: 'OK'
    })
  }

  function removeFlowLog(index: number) {
    setFlowLogs(prev => prev.filter((_, i) => i !== index))
  }

  function getSeverityColor(severity: string) {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-600 text-white'
      case 'HIGH': return 'bg-orange-500 text-white'
      case 'MEDIUM': return 'bg-yellow-500 text-black'
      case 'LOW': return 'bg-blue-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">NetWatch</h1>
            <nav className="flex space-x-4">
              <button
                onClick={() => setActiveTab('detection')}
                className={`px-3 py-2 rounded-md text-sm font-medium ${
                  activeTab === 'detection'
                    ? 'bg-indigo-600 text-white'
                    : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
                }`}
              >
                Detection
              </button>
              <button
                onClick={() => setActiveTab('ingestion')}
                className={`px-3 py-2 rounded-md text-sm font-medium ${
                  activeTab === 'ingestion'
                    ? 'bg-indigo-600 text-white'
                    : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
                }`}
              >
                Ingestion
              </button>
              <button
                onClick={() => setActiveTab('security-audit')}
                className={`px-3 py-2 rounded-md text-sm font-medium ${
                  activeTab === 'security-audit'
                    ? 'bg-indigo-600 text-white'
                    : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
                }`}
              >
                Security Audit
              </button>
            </nav>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-300">
            {error}
          </div>
        )}

        {activeTab === 'detection' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">Threat Detection</h2>
              <button
                onClick={analyzeFlowLogs}
                disabled={loading}
                className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Analyzing...' : 'Analyze Flow Logs'}
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Flow Log Input</h3>
                
                <div className="space-y-4 mb-4">
                  <div className="grid grid-cols-2 gap-4">
                    <input
                      type="text"
                      placeholder="Account ID"
                      value={newFlowLog.account_id}
                      onChange={(e) => handleFlowLogChange('account_id', e.target.value)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                    <input
                      type="text"
                      placeholder="Interface ID"
                      value={newFlowLog.interface_id}
                      onChange={(e) => handleFlowLogChange('interface_id', e.target.value)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <input
                      type="text"
                      placeholder="Source IP"
                      value={newFlowLog.src_addr}
                      onChange={(e) => handleFlowLogChange('src_addr', e.target.value)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                    <input
                      type="text"
                      placeholder="Destination IP"
                      value={newFlowLog.dst_addr}
                      onChange={(e) => handleFlowLogChange('dst_addr', e.target.value)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>
                  <div className="grid grid-cols-4 gap-4">
                    <input
                      type="number"
                      placeholder="Source Port"
                      value={newFlowLog.src_port}
                      onChange={(e) => handleFlowLogChange('src_port', parseInt(e.target.value) || 0)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                    <input
                      type="number"
                      placeholder="Dest Port"
                      value={newFlowLog.dst_port}
                      onChange={(e) => handleFlowLogChange('dst_port', parseInt(e.target.value) || 0)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                    <input
                      type="number"
                      placeholder="Protocol"
                      value={newFlowLog.protocol}
                      onChange={(e) => handleFlowLogChange('protocol', parseInt(e.target.value) || 6)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                    <select
                      value={newFlowLog.action}
                      onChange={(e) => handleFlowLogChange('action', e.target.value)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    >
                      <option value="ACCEPT">ACCEPT</option>
                      <option value="REJECT">REJECT</option>
                    </select>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <input
                      type="number"
                      placeholder="Packets"
                      value={newFlowLog.packets}
                      onChange={(e) => handleFlowLogChange('packets', parseInt(e.target.value) || 0)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                    <input
                      type="number"
                      placeholder="Bytes"
                      value={newFlowLog.bytes}
                      onChange={(e) => handleFlowLogChange('bytes', parseInt(e.target.value) || 0)}
                      className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>
                </div>
                
                <button
                  onClick={addFlowLog}
                  className="w-full px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600"
                >
                  Add Flow Log
                </button>

                {flowLogs.length > 0 && (
                  <div className="mt-4 space-y-2">
                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Added Flow Logs ({flowLogs.length})</h4>
                    {flowLogs.map((log, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded text-sm">
                        <span>{log.src_addr}:{log.src_port} → {log.dst_addr}:{log.dst_port} ({log.action})</span>
                        <button
                          onClick={() => removeFlowLog(idx)}
                          className="text-red-500 hover:text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Detection Rules</h3>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {detectionRules.map((rule) => (
                    <div key={rule.id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded">
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">{rule.name}</p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">{rule.id}</p>
                      </div>
                      <span className={`px-2 py-1 text-xs rounded ${getSeverityColor(rule.severity)}`}>
                        {rule.severity}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {detectionResults.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Detection Results ({detectionResults.length})</h3>
                <div className="space-y-3">
                  {detectionResults.map((result, idx) => (
                    <div key={idx} className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg border-l-4 border-indigo-500">
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">{result.rule_name}</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">{result.rule_id}</p>
                        </div>
                        <span className={`px-2 py-1 text-xs rounded ${getSeverityColor(result.severity)}`}>
                          {result.severity}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-300">{result.details}</p>
                      <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                        {result.flow_log.src_addr}:{result.flow_log.src_port} → {result.flow_log.dst_addr}:{result.flow_log.dst_port} | {new Date(result.timestamp).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'ingestion' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">Flow Log Ingestion</h2>
            
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Upload Flow Logs</h3>
              <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-8 text-center">
                <input
                  type="file"
                  accept=".json,.log,.gz"
                  className="hidden"
                  id="file-upload"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) {
                      alert(`File selected: ${file.name}. Ingestion would upload to ${API_BASE}/api/v1/ingestion/flow-logs`)
                    }
                  }}
                />
                <label htmlFor="file-upload" className="cursor-pointer">
                  <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                  <p className="mt-2 text-gray-600 dark:text-gray-400">Drag and drop or click to select flow log files</p>
                  <p className="text-sm text-gray-500 dark:text-gray-500">Supported formats: .json, .log, .gz</p>
                </label>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Recent Ingestion Jobs</h3>
              <table className="w-full">
                <thead>
                  <tr className="text-left text-sm text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                    <th className="pb-3 font-medium">Job ID</th>
                    <th className="pb-3 font-medium">Source</th>
                    <th className="pb-3 font-medium">Status</th>
                    <th className="pb-3 font-medium">Records Processed</th>
                    <th className="pb-3 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-gray-100 dark:border-gray-800">
                    <td className="py-3 text-sm text-gray-900 dark:text-white">job-001</td>
                    <td className="py-3 text-sm text-gray-500 dark:text-gray-400">sample-flow-logs.json</td>
                    <td className="py-3"><span className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded">Completed</span></td>
                    <td className="py-3 text-sm text-gray-900 dark:text-white">150</td>
                    <td className="py-3 text-sm text-gray-500 dark:text-gray-400">2026-01-01</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'security-audit' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">Security Group Audit</h2>
              <button
                onClick={analyzeSecurityGroups}
                disabled={loading}
                className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Auditing...' : 'Analyze Security Groups'}
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Security Group Input</h3>
                <div className="space-y-4">
                  <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded">
                    <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">Test Security Group (sg-12345)</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Contains rule: SSH (port 22) open to 0.0.0.0/0</p>
                  </div>
                </div>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Audit Rules</h3>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {auditRules.map((rule) => (
                    <div key={rule.id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded">
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">{rule.name}</p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">{rule.id}</p>
                      </div>
                      <span className={`px-2 py-1 text-xs rounded ${getSeverityColor(rule.severity)}`}>
                        {rule.severity}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {auditFindings.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Audit Findings ({auditFindings.length})</h3>
                <div className="space-y-3">
                  {auditFindings.map((finding, idx) => (
                    <div key={idx} className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg border-l-4 border-red-500">
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">{finding.title}</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">{finding.resource_id} ({finding.resource_type})</p>
                        </div>
                        <span className={`px-2 py-1 text-xs rounded ${getSeverityColor(finding.severity)}`}>
                          {finding.severity}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-300">{finding.description}</p>
                      <p className="text-sm text-indigo-600 dark:text-indigo-400 mt-1">Remediation: {finding.remediation}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <p className="text-center text-sm text-gray-500 dark:text-gray-400">
            NetWatch v0.1.0 - Network Threat Detection & Security Audit
          </p>
        </div>
      </footer>
    </div>
  )
}

export default App