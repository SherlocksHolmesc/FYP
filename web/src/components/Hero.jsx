import { Canvas } from '@react-three/fiber'
import { OrbitControls, Sphere, MeshDistortMaterial } from '@react-three/drei'
import { motion } from 'framer-motion'
import './Hero.css'

function AnimatedSphere() {
  return (
    <Sphere args={[1, 100, 200]} scale={2.5}>
      <MeshDistortMaterial
        color="#ff007a"
        attach="material"
        distort={0.5}
        speed={2}
        roughness={0.2}
      />
    </Sphere>
  )
}

function Hero() {
  return (
    <section className="hero">
      <div className="container">
        <div className="hero-content">
          <motion.div
            className="hero-text"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <h1 className="hero-title">
              Protect Your Web3
              <span className="gradient-text"> Journey</span>
            </h1>
            <p className="hero-subtitle">
              Advanced AI-powered risk detection for Ethereum addresses and dApps.
              Stay safe from scams, phishing, and malicious contracts.
            </p>
            <div className="hero-buttons">
              <a href="#checker" className="btn btn-primary">
                Try Scanner
              </a>
              <a
                href="https://github.com/yourusername/FYP"
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-secondary"
              >
                View on GitHub
              </a>
            </div>
            <div className="hero-stats">
              <div className="stat">
                <div className="stat-value">3,580+</div>
                <div className="stat-label">Known Scams Detected</div>
              </div>
              <div className="stat">
                <div className="stat-value">95%</div>
                <div className="stat-label">Detection Accuracy</div>
              </div>
              <div className="stat">
                <div className="stat-value">Real-time</div>
                <div className="stat-label">Protection</div>
              </div>
            </div>
          </motion.div>
          <motion.div
            className="hero-visual"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1, delay: 0.3 }}
          >
            <Canvas camera={{ position: [0, 0, 5] }}>
              <ambientLight intensity={0.5} />
              <directionalLight position={[10, 10, 5]} intensity={1} />
              <AnimatedSphere />
              <OrbitControls enableZoom={false} autoRotate autoRotateSpeed={2} />
            </Canvas>
          </motion.div>
        </div>
      </div>
    </section>
  )
}

export default Hero
