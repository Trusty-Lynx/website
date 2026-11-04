
import { Routes } from '@angular/router';
import { Dashboard } from './pages/dashboard/dashboard';
import { Tresor } from './pages/tresor/tresor';
import { Einstellungen } from './pages/einstellungen/einstellungen';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard', component: Dashboard },
  { path: 'tresor', component: Tresor },
  { path: 'einstellungen', component: Einstellungen },
  { path: '**', redirectTo: 'dashboard' }
];
