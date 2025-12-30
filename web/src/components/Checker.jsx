import { useState } from 'react'
import { motion } from 'framer-motion'
import axios from 'axios'
import './Checker.css'

const API_URL = 'http://localhost:5000'

function Checker() {
  const [activeTab, setActiveTab] = useState('address')
  const [addressInput, setAddressInput] = useState('')
  const [websiteInput, setWebsiteInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const checkAddress = async () => {
    if (!addressInput || addressInput.length !== 42) {
      setError('Please enter a valid Ethereum address (0x...)')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await axios.get(`${API_URL}/score/${addressInput}`)
      setResult({ type: 'address', data: response.data })
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to check address. Make sure the API is running.')
    } finally {
      setLoading(false)
    }
  }

  const checkWebsite = async () => {
    if (!websiteInput) {
      setError('Please enter a website URL')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await axios.get(`${API_URL}/site`, {
        params: { url: websiteInput }
      })
      setResult({ type: 'website', data: response.data })
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to check website. Make sure the API is running.')
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (score) => {
    if (score >= 80) return '#dc3545'
    if (score >= 50) return '#fd7e14'
    if (score >= 30) return '#ffc107'
    return '#27ae60'
  }

  const getRiskLevel = (score) => {
    if (score >= 80) return 'DANGEROUS'
    if (score >= 50) return 'SUSPICIOUS'
    if (score >= 30) return 'CAUTION'
    return 'SAFE'
  }

  return (
    <section className="checker" id="checker">
      <div className="container">
        <motion.div
          className="checker-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
        >
          <h2 className="section-title">Security Scanner</h2>
          <p className="section-subtitle">
            Check any Ethereum address or dApp website for potential risks
          </p>
        </motion.div>

        <motion.div
          className="checker-card card"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.2 }}
        >
          <div className="checker-tabs">
            <button
              className={`tab ${activeTab === 'address' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('address')
                setResult(null)
                setError(null)
              }}
            >
              Ethereum Address
            </button>
            <button
              className={`tab ${activeTab === 'website' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('website')
                setResult(null)
                setError(null)
              }}
            >
              Website / dApp
            </button>
          </div>

          <div className="checker-content">
            {activeTab === 'address' ? (
              <div className="input-group">
                <input
                  type="text"
                  className="input"
                  placeholder="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
                  value={addressInput}
                  onChange={(e) => setAddressInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && checkAddress()}
                />
                <button
                  className="btn btn-primary"
                  onClick={checkAddress}
                  disabled={loading}
                >
                  {loading ? 'Scanning...' : 'Check Address'}
                </button>
              </div>
            ) : (
              <div className="input-group">
                <input
                  type="text"
                  className="input"
                  placeholder="https://example.com"
                  value={websiteInput}
                  onChange={(e) => setWebsiteInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && checkWebsite()}
                />
                <button
                  className="btn btn-primary"
                  onClick={checkWebsite}
                  disabled={loading}
                >
                  {loading ? 'Scanning...' : 'Check Website'}
                </button>
              </div>
            )}

            {error && (
              <motion.div
                className="error-message"
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
              >
                {error}
              </motion.div>
            )}

            {result && (
              <motion.div
                className="result"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
              >
                <div className="result-header">
                  <div
                    className="risk-score"
                    style={{ color: getRiskColor(result.data.score) }}
                  >
                    {result.data.score}
                  </div>
                  <div
                    className="risk-badge"
                    style={{
                      background: getRiskColor(result.data.score),
                    }}
                  >
                    {result.type === 'website'
                      ? result.data.verdict
                      : getRiskLevel(result.data.score)}
                  </div>
                </div>

                {result.type === 'address' && (
                  <div className="result-details">
                    <div className="detail-row">
                      <span className="detail-label">Prediction:</span>
                      <span className="detail-value">
                        {result.data.prediction}
                      </span>
                    </div>
                    {result.data.is_honeypot && (
                      <div className="warning-badge">HONEYPOT DETECTED</div>
                    )}
                    {result.data.goplus_flags &&
                      result.data.goplus_flags.length > 0 && (
                        <div className="flags">
                          <div className="flags-title">Risk Flags:</div>
                          <div className="flags-list">
                            {result.data.goplus_flags.map((flag, i) => (
                              <span key={i} className="flag">
                                {flag}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    {result.data.components && (
                      <div className="components">
                        <div className="component-title">Score Breakdown:</div>
                        <div className="component-bars">
                          {result.data.components.ml_score !== null && (
                            <div className="component">
                              <span>ML Model</span>
                              <div className="bar">
                                <div
                                  className="bar-fill"
                                  style={{
                                    width: `${result.data.components.ml_score}%`,
                                    background: getRiskColor(
                                      result.data.components.ml_score
                                    ),
                                  }}
                                />
                              </div>
                              <span>{result.data.components.ml_score}</span>
                            </div>
                          )}
                          {result.data.components.goplus_score !== null && (
                            <div className="component">
                              <span>GoPlus</span>
                              <div className="bar">
                                <div
                                  className="bar-fill"
                                  style={{
                                    width: `${result.data.components.goplus_score}%`,
                                    background: getRiskColor(
                                      result.data.components.goplus_score
                                    ),
                                  }}
                                />
                              </div>
                              <span>{result.data.components.goplus_score}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {result.type === 'website' && (
                  <div className="result-details">
                    {result.data.is_phishing && (
                      <div className="warning-badge">
                        KNOWN PHISHING SITE
                      </div>
                    )}
                    {result.data.is_verified_dapp && (
                      <div className="success-badge">
                        Verified dApp
                      </div>
                    )}
                    {result.data.is_audited && (
                      <div className="success-badge">
                        Audited Contracts
                      </div>
                    )}
                    {result.data.flags && result.data.flags.length > 0 && (
                      <div className="flags">
                        <div className="flags-title">Findings:</div>
                        <div className="flags-list">
                          {result.data.flags.map((flag, i) => (
                            <span
                              key={i}
                              className={`flag ${
                                flag.includes('✓') ? 'positive' : ''
                              }`}
                            >
                              {flag}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </motion.div>
            )}
          </div>
        </motion.div>
      </div>
    </section>
  )
}

export default Checker
