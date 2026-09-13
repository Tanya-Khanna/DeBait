import { Landing } from './pages/Landing';
import { Workspace, Evaluations } from './pages/Utility';

export function AppRouter() {
  const path = window.location.pathname;
  return path === '/app' ? <Workspace /> : path === '/evaluations' ? <Evaluations /> : <Landing />;
}
