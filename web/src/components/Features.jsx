import { motion } from 'framer-motion'
import './Features.css'

const features = [
  {
    icon: '🛡️',
    title: 'Multi-Layer Detection',
    description: 'Combines ML models, GoPlus API, and blacklist databases for comprehensive protection.'
  },
  {
    icon: '🤖',
    title: 'AI-Powered Analysis',
    description: 'Machine learning trained on 667+ verified fraud cases with 95% accuracy.'
  },
  {
    icon: '⚡',
    title: 'Real-Time Scanning',
    description: 'Instant risk assessment before you interact with any address or dApp.'
  },
  {
    icon: '🎯',
    title: 'Low False Positives',
    description: 'Intelligent hybrid scoring reduces false alarms while catching real threats.'
  },
  {
    icon: '🌐',
    title: 'Website Verification',
    description: 'Check if dApps are verified, audited, or flagged as phishing sites.'
  },
  {
    icon: '🔍',
    title: 'Transaction Analysis',
    description: 'Deep inspection of approval requests, permits, and suspicious patterns.'
  }
]

function Features() {
  return (
    <section className="features" id="features">
      <div className="container">
        <motion.div
          className="features-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
        >
          <h2 className="section-title">Built for Maximum Protection</h2>
          <p className="section-subtitle">
            Advanced security features designed to keep your crypto safe
          </p>
        </motion.div>
        <div className="features-grid">
          {features.map((feature, index) => (
            <motion.div
              key={index}
              className="feature-card card"
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
            >
              <div className="feature-icon">{feature.icon}</div>
              <h3 className="feature-title">{feature.title}</h3>
              <p className="feature-description">{feature.description}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}

export default Features
