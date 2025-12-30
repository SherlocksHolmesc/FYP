import './Footer.css'

function Footer() {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-content">
          <div className="footer-brand">
            <h3 className="footer-logo">Web3 Risk Guard</h3>
            <p className="footer-tagline">
              AI-powered security for the decentralized web
            </p>
          </div>
          <div className="footer-links">
            <div className="footer-column">
              <h4 className="footer-heading">Product</h4>
              <a href="#features" className="footer-link">Features</a>
              <a href="#checker" className="footer-link">Scanner</a>
              <a href="https://github.com/yourusername/FYP" target="_blank" rel="noopener noreferrer" className="footer-link">
                Browser Extension
              </a>
            </div>
            <div className="footer-column">
              <h4 className="footer-heading">Resources</h4>
              <a href="https://github.com/yourusername/FYP" target="_blank" rel="noopener noreferrer" className="footer-link">
                Documentation
              </a>
              <a href="https://github.com/yourusername/FYP" target="_blank" rel="noopener noreferrer" className="footer-link">
                GitHub
              </a>
              <a href="https://gopluslabs.io" target="_blank" rel="noopener noreferrer" className="footer-link">
                GoPlus API
              </a>
            </div>
            <div className="footer-column">
              <h4 className="footer-heading">About</h4>
              <a href="#" className="footer-link">FYP Project</a>
              <a href="#" className="footer-link">Contact</a>
            </div>
          </div>
        </div>
        <div className="footer-bottom">
          <p className="footer-copyright">
            Built with React, Three.js & Flask. Final Year Project 2024.
          </p>
        </div>
      </div>
    </footer>
  )
}

export default Footer
