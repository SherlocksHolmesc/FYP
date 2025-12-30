import { useState } from 'react'
import Hero from './components/Hero'
import Features from './components/Features'
import Checker from './components/Checker'
import Footer from './components/Footer'
import './App.css'

function App() {
  return (
    <div className="app">
      <Hero />
      <Features />
      <Checker />
      <Footer />
    </div>
  )
}

export default App
