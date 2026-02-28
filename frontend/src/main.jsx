import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import RootScope from '../../RootScope.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <RootScope />
  </StrictMode>,
)
