import React from 'react';
import { createRoot } from 'react-dom/client';
import { AppRouter } from './router';
import './styles/tokens.css';
import './styles/landing.css';

createRoot(document.getElementById('root')!).render(<React.StrictMode><AppRouter /></React.StrictMode>);
