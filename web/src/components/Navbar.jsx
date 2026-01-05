import { Link, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import './Navbar.css'

function Navbar() {
  const location = useLocation()

  return (
    <motion.nav
      className="navbar"
      initial={{ y: -100, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.8, ease: "easeOut" }}
    >
      <div className="navbar-inner">
        <Link to="/" className="navbar-logo">
          <span className="logo-text">GUARDCHAIN</span>
        </Link>

        <div className="navbar-links">
          <Link
            to="/"
            className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
          >
            <span className="nav-number">00</span>
            <span className="nav-text">HOME</span>
          </Link>
          <a href="/#features" className="nav-link">
            <span className="nav-number">01</span>
            <span className="nav-text">FEATURES</span>
          </a>
          <Link
            to="/scanner"
            className={`nav-link ${location.pathname === '/scanner' ? 'active' : ''}`}
          >
            <span className="nav-number">02</span>
            <span className="nav-text">SCANNER</span>
          </Link>
          <a
            href="https://github.com/SherlocksHolmesc/FYP"
            target="_blank"
            rel="noopener noreferrer"
            className="nav-link"
          >
            <span className="nav-number">03</span>
            <span className="nav-text">GITHUB</span>
          </a>
        </div>

        <Link to="/scanner" className="navbar-cta">
          LAUNCH
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
            <path d="M7 17L17 7M17 7H7M17 7V17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </Link>
      </div>
    </motion.nav>
  )
}

export default Navbar
