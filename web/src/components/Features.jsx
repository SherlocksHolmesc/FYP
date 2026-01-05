import { motion } from 'framer-motion'
import './Features.css'

const features = [
  {
    number: '01',
    title: 'MULTI-LAYER DETECTION',
    description: 'COMBINES ML MODELS, GOPLUS API, AND BLACKLIST DATABASES FOR COMPREHENSIVE PROTECTION AGAINST ALL THREAT TYPES.',
  },
  {
    number: '02',
    title: 'AI-POWERED ANALYSIS',
    description: 'MACHINE LEARNING TRAINED ON 667+ VERIFIED FRAUD CASES ACHIEVING 95% ACCURACY IN SCAM DETECTION.',
  },
  {
    number: '03',
    title: 'REAL-TIME SCANNING',
    description: 'INSTANT RISK ASSESSMENT BEFORE YOU INTERACT WITH ANY ADDRESS, CONTRACT, OR DAPP WEBSITE.',
  },
  {
    number: '04',
    title: 'LOW FALSE POSITIVES',
    description: 'INTELLIGENT HYBRID SCORING SYSTEM REDUCES FALSE ALARMS WHILE CATCHING REAL THREATS ACCURATELY.',
  },
  {
    number: '05',
    title: 'WEBSITE VERIFICATION',
    description: 'CHECK IF DAPPS ARE VERIFIED, AUDITED, OR FLAGGED AS KNOWN PHISHING SITES BEFORE CONNECTING.',
  },
  {
    number: '06',
    title: 'TRANSACTION ANALYSIS',
    description: 'DEEP INSPECTION OF APPROVAL REQUESTS, PERMITS, AND SUSPICIOUS TRANSACTION PATTERNS.',
  }
]

function Features() {
  return (
    <section className="features" id="features">
      <div className="features-header">
        <motion.span 
          className="section-number"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
        >
          01
        </motion.span>
        <motion.h2 
          className="features-title"
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8 }}
        >
          FEATURES
          <span className="title-chinese">功能</span>
        </motion.h2>
        <motion.p 
          className="features-description"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8, delay: 0.2 }}
        >
          ADVANCED SECURITY FEATURES DESIGNED TO KEEP YOUR CRYPTO SAFE FROM MODERN 
          THREATS. WE ANALYZE SMART CONTRACTS, TRANSACTION PATTERNS, AND ON-CHAIN DATA 
          TO PROVIDE COMPREHENSIVE PROTECTION.
        </motion.p>
      </div>

      <div className="features-grid">
        {features.map((feature, index) => (
          <motion.div
            key={index}
            className="feature-item"
            initial={{ opacity: 0, y: 40 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, delay: index * 0.1 }}
          >
            <span className="feature-number">{feature.number}</span>
            <h3 className="feature-title">{feature.title}</h3>
            <p className="feature-description">{feature.description}</p>
          </motion.div>
        ))}
      </div>

      {/* Marquee divider */}
      <div className="features-marquee">
        <div className="marquee-track">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="marquee-content">
              <span>TECHNOLOGY IS SECURITY</span>
              <span className="marquee-dot">◆</span>
              <span>GLOBAL FROM DAY ONE</span>
              <span className="marquee-dot">◆</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

export default Features
