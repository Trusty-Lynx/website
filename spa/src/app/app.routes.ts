import { Routes } from '@angular/router';
import { Dashboard } from './pages/dashboard/dashboard';
import { Tresor } from './pages/tresor/tresor';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard', component: Dashboard },
  { path: 'tresor', component: Tresor },
  { path: '**', redirectTo: 'dashboard' }
];
