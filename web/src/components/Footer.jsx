import { Link } from 'react-router-dom'
import './Footer.css'

function Footer() {
  return (
    <footer className="footer">
      <div className="footer-content">
        {/* Left - Big Text */}
        <div className="footer-brand">
          <h2 className="footer-tagline">
            SECURE FROM
            <br />
            <span className="highlight">DAY ONE</span>
          </h2>
        </div>

        {/* Right - Links Grid */}
        <div className="footer-links">
          <div className="footer-column">
            <Link to="/" className="footer-link">
              <span className="link-number">00</span>
              <span className="link-text">HOME</span>
            </Link>
            <a href="/#features" className="footer-link">
              <span className="link-number">01</span>
              <span className="link-text">FEATURES</span>
            </a>
            <Link to="/scanner" className="footer-link">
              <span className="link-number">02</span>
              <span className="link-text">SCANNER</span>
            </Link>
          </div>
          <div className="footer-column">
            <a href="https://github.com/SherlocksHolmesc/FYP" target="_blank" rel="noopener noreferrer" className="footer-link">
              <span className="link-number">03</span>
              <span className="link-text">GITHUB</span>
            </a>
            <a href="https://gopluslabs.io" target="_blank" rel="noopener noreferrer" className="footer-link">
              <span className="link-number">04</span>
              <span className="link-text">GOPLUS API</span>
            </a>
            <a href="https://etherscan.io" target="_blank" rel="noopener noreferrer" className="footer-link">
              <span className="link-number">05</span>
              <span className="link-text">ETHERSCAN</span>
            </a>
          </div>
        </div>
      </div>

      {/* Bottom Bar */}
      <div className="footer-bottom">
        <div className="footer-bottom-left">
          <span className="footer-logo">GUARDCHAIN</span>
        </div>
        <div className="footer-bottom-center">
          <span className="footer-copyright">
            © 2024 GUARDCHAIN — FINAL YEAR PROJECT
          </span>
        </div>
        <div className="footer-bottom-right">
          <a 
            href="https://github.com/SherlocksHolmesc/FYP" 
            target="_blank" 
            rel="noopener noreferrer"
            className="social-link"
          >
            GITHUB
          </a>
        </div>
      </div>
    </footer>
  )
}

export default Footer
