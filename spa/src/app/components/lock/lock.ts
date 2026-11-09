import { Component, inject, signal } from '@angular/core';
import { VaultService } from '../../core/vault.service';

@Component({
  selector: 'app-lock',
  templateUrl: './lock.html',
  styleUrl: './lock.css',
})
export class Lock {
  protected vault = inject(VaultService);

  protected mode = signal<'loading' | 'create' | 'unlock' | 'error'>('loading');
  protected error = signal('');
  protected busy = signal(false);

  constructor() {
    this.check();
  }

  private async check() {
    const result = await this.vault.checkVault();
    this.mode.set(result ?? 'error');
  }

  async unlock(event: Event, passwordInput: HTMLInputElement) {
    event.preventDefault();
    this.error.set('');

    if (!passwordInput.value) {
      this.error.set('Bitte Masterpasswort eingeben.');
      return;
    }

    this.busy.set(true);
    const message = await this.vault.unlock(passwordInput.value);
    this.busy.set(false);

    if (message) {
      this.error.set(message);
    } else {
      passwordInput.value = '';
    }
  }

  async create(event: Event, password: string, passwordConfirm: string, confirmed: boolean) {
    event.preventDefault();
    this.error.set('');

    if (password.length < 12) {
      this.error.set('Das Masterpasswort muss mindestens 12 Zeichen lang sein.');
      return;
    }
    if (password !== passwordConfirm) {
      this.error.set('Die Masterpasswörter stimmen nicht überein.');
      return;
    }
    if (!confirmed) {
      this.error.set('Bitte bestätige, dass ein vergessenes Masterpasswort nicht wiederherstellbar ist.');
      return;
    }

    this.busy.set(true);
    const message = await this.vault.create(password);
    this.busy.set(false);

    if (message === 'exists') {
      this.mode.set('unlock');
    } else if (message) {
      this.error.set(message);
    }
  }
}
