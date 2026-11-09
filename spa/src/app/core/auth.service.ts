import { Injectable } from '@angular/core';
import { API_BASE, LOGIN_PAGE } from './config';

@Injectable({ providedIn: 'root' })
export class AuthService {
  readonly loginToken = sessionStorage.getItem('loginToken');
  readonly userId = sessionStorage.getItem('userId') ?? '';
  readonly email = sessionStorage.getItem('email') ?? '';
  readonly previousLogin = sessionStorage.getItem('previousLogin') ?? '';

  isLoggedIn(): boolean {
    return this.loginToken !== null;
  }

  goToLogin(expired = false): void {
    sessionStorage.clear();
    window.location.href = LOGIN_PAGE + (expired ? '?abgelaufen' : '');
  }

  async logout(): Promise<void> {
    try {
      await fetch(API_BASE + '/logout', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + this.loginToken },
      });
    } catch (error) {
      console.error(error);
    }
    this.goToLogin();
  }
}
