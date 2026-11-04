import { Component, inject } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { AuthService } from './core/auth.service';
import { VaultService } from './core/vault.service';
import { Lock } from './components/lock/lock';

@Component({
  imports: [RouterOutlet, RouterLink, RouterLinkActive, Lock],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  protected auth = inject(AuthService);
  protected vault = inject(VaultService);

  constructor() {
    // Ohne Login zurück zur MPA
    if (!this.auth.isLoggedIn()) {
      this.auth.goToLogin();
    }

    // Jede Aktivität startet die 15-Minuten-Auto-Sperre neu
    for (const type of ['click', 'keydown', 'mousemove', 'scroll']) {
      document.addEventListener(type, () => this.vault.resetAutoLock(), { passive: true });
    }
  }
}
