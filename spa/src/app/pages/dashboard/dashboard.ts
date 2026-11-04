import { Component, inject } from '@angular/core';
import { AuthService } from '../../core/auth.service';
import { BreachService } from '../../core/breach.service';
import { VaultService } from '../../core/vault.service';

@Component({
  imports: [],
  selector: 'app-dashboard',
  styleUrl: './dashboard.css',
  templateUrl: './dashboard.html',
})
export class Dashboard {
  protected vault = inject(VaultService);
  protected breach = inject(BreachService);
  private auth = inject(AuthService);

  protected lastLogin = this.auth.previousLogin
    ? new Date(Number(this.auth.previousLogin)).toLocaleString('de-DE', {
      day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit',
    }) + ' Uhr'
    : 'Erster Login';
}
