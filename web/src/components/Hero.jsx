import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import './Hero.css'

const words = ['SCAMS', 'HONEYPOTS', 'RUG PULLS', 'EXPLOITS', 'PHISHING']
const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%&*<>[]{}?/\\|0123456789'

function ScrambleText({ words, interval = 3500 }) {
  const [currentIndex, setCurrentIndex] = useState(0)
  const [displayText, setDisplayText] = useState(words[0])
  const [isScrambling, setIsScrambling] = useState(false)
  const animationRef = useRef(null)

  useEffect(() => {
    // Initial scramble effect on mount
    scrambleToWord(words[0])
  }, [])

  const scrambleToWord = (targetWord) => {
    if (animationRef.current) {
      cancelAnimationFrame(animationRef.current)
    }

    setIsScrambling(true)
    
    const iterations = 15 // Number of scramble cycles before resolving
    const resolveDelay = 80 // ms between each character resolving
    let currentIteration = 0
    let resolvedCount = 0
    
    const targetLength = targetWord.length
    
    const animate = () => {
      currentIteration++
      
      let result = ''
      
      for (let i = 0; i < targetLength; i++) {
        if (i < resolvedCount) {
          // This character is resolved
          result += targetWord[i]
        } else {
          // This character is still scrambling
          result += chars[Math.floor(Math.random() * chars.length)]
        }
      }
      
      setDisplayText(result)
      
      // Check if we should resolve the next character
      if (currentIteration > iterations && currentIteration % 3 === 0) {
        resolvedCount++
      }
      
      // Continue animation until all characters are resolved
      if (resolvedCount <= targetLength) {
        animationRef.current = requestAnimationFrame(animate)
      } else {
        setDisplayText(targetWord)
        setIsScrambling(false)
      }
    }
    
    animationRef.current = requestAnimationFrame(animate)
  }

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentIndex((prev) => {
        const nextIndex = (prev + 1) % words.length
        scrambleToWord(words[nextIndex])
        return nextIndex
      })
    }, interval)

    return () => {
      clearInterval(timer)
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
    }
  }, [interval])

  return (
    <span className={`scramble-text ${isScrambling ? 'scrambling' : ''}`}>
      {displayText.split('').map((char, i) => (
        <span 
          key={i} 
          className="scramble-char"
          style={{ 
            animationDelay: `${i * 0.02}s`,
            opacity: char === ' ' ? 0 : 1 
          }}
        >
          {char === ' ' ? '\u00A0' : char}
        </span>
      ))}
    </span>
  )
}

function Hero() {
  return (
    <section className="hero">
      <div className="hero-content">
        {/* Section Number */}
        <motion.div 
          className="section-number"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 1, delay: 0.2 }}
        >
          00
        </motion.div>

        {/* Main Headline */}
        <motion.div 
          className="hero-headline"
          initial={{ opacity: 0, y: 60 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1, delay: 0.3 }}
        >
          <h1 className="hero-title">
            <span className="title-line">GUARDCHAIN</span>
            <span className="title-line">PROTECTS YOU</span>
            <span className="title-line">FROM</span>
            <span className="title-line rotating-word-container">
              <ScrambleText words={words} interval={3000} />
            </span>
          </h1>
        </motion.div>

        {/* Right Side Info */}
        <motion.div 
          className="hero-info"
          initial={{ opacity: 0, x: 40 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 1, delay: 0.6 }}
        >
          <p className="hero-description">
            AI-POWERED BLOCKCHAIN SECURITY FOR ETHEREUM. DETECT MALICIOUS 
            SMART CONTRACTS BEFORE YOU SIGN.
          </p>
          <Link to="/scanner" className="hero-cta">
            <span>LAUNCH SCANNER</span>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M7 17L17 7M17 7H7M17 7V17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </Link>
        </motion.div>

        {/* Stats Bar */}
        <motion.div 
          className="hero-stats-bar"
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1, delay: 0.9 }}
        >
          <div className="stat-item">
            <span className="stat-number">95%</span>
            <span className="stat-label">ACCURACY</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">3,580+</span>
            <span className="stat-label">SCAMS DETECTED</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">2024</span>
            <span className="stat-label">YEAR FOUNDED</span>
          </div>
        </motion.div>
      </div>

      {/* Marquee */}
      <div className="hero-marquee">
        <div className="marquee-track">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="marquee-content">
              <span>BLOCKCHAIN SECURITY</span>
              <span className="marquee-dot">◆</span>
              <span>ML DETECTION</span>
              <span className="marquee-dot">◆</span>
              <span>REAL-TIME SCANNING</span>
              <span className="marquee-dot">◆</span>
              <span>GOPLUS API</span>
              <span className="marquee-dot">◆</span>
              <span>SMART CONTRACT ANALYSIS</span>
              <span className="marquee-dot">◆</span>
            </div>
          ))}
        </div>
      </div>

      {/* Scroll Indicator */}
      <motion.div 
        className="scroll-indicator"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
      >
        <motion.span
          animate={{ y: [0, 8, 0] }}
          transition={{ duration: 1.5, repeat: Infinity }}
        >
          ↓
        </motion.span>
      </motion.div>
    </section>
  )
}

export default Hero
