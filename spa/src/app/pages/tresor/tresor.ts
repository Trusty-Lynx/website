import { Component, ElementRef, inject, signal, viewChild } from '@angular/core';
import { VaultItem, VaultService } from '../../core/vault.service';

@Component({
  selector: 'app-tresor',
  templateUrl: './tresor.html',
  styleUrl: './tresor.css',
})
export class Tresor {
  protected vault = inject(VaultService);

  protected formOpen = signal(false);
  protected editing = signal<VaultItem | null>(null);
  protected formPassword = signal('');
  protected formError = signal('');
  protected busy = signal(false);

  protected revealed = signal<Record<string, string>>({});
  protected copiedId = signal<string | null>(null);

  private deleteDialog = viewChild.required<ElementRef<HTMLDialogElement>>('deleteDialog');

  async toggleSecret(item: VaultItem) {
    if (this.revealed()[item.id] !== undefined) {
      this.revealed.update(({ [item.id]: _, ...rest }) => rest);
      return;
    }
    const password = await this.vault.fetchSecret(item);
    if (password !== null) {
      this.revealed.update((all) => ({ ...all, [item.id]: password }));
    }
  }

  async copySecret(item: VaultItem) {
    const password = await this.vault.fetchSecret(item);
    if (password === null) {
      return;
    }
    try {
      await navigator.clipboard.writeText(password);
      this.copiedId.set(item.id);
      setTimeout(() => this.copiedId.set(null), 1500);
      setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000);
    } catch (error) {
      console.error(error);
      this.vault.error.set('Kopieren nicht möglich.');
    }
  }

  async openForm(item: VaultItem | null) {
    this.formError.set('');
    this.formPassword.set('');
    this.editing.set(item);

    if (item) {
      const password = await this.vault.fetchSecret(item);
      if (password === null) {
        return;
      }
      this.formPassword.set(password);
    }
    this.formOpen.set(true);
  }

  closeForm() {
    this.formOpen.set(false);
    this.editing.set(null);
    this.formPassword.set('');
    this.formError.set('');
  }

  async save(event: Event, title: string, url: string, user: string, password: string, alg: string) {
    event.preventDefault();
    this.formError.set('');

    if (!title.trim() || !password) {
      this.formError.set('Bitte mindestens Titel und Passwort eingeben.');
      return;
    }

    this.busy.set(true);
    const message = await this.vault.saveItem(this.editing(), {
      title: title.trim(), url: url.trim(), user: user.trim(), password: password, alg: alg,
    });
    this.busy.set(false);

    if (message && message !== 'close') {
      this.formError.set(message);
      return;
    }
    this.closeForm();
  }

  private confirmDelete(): Promise<boolean> {
    const dialog = this.deleteDialog().nativeElement;
    return new Promise((resolve) => {
      dialog.onclose = () => resolve(dialog.returnValue === 'delete');
      dialog.returnValue = '';
      dialog.showModal();
    });
  }

  async remove() {
    const item = this.editing();
    if (!item || !(await this.confirmDelete())) {
      return;
    }

    this.busy.set(true);
    const message = await this.vault.deleteItem(item);
    this.busy.set(false);

    if (message) {
      this.formError.set(message);
      return;
    }
    this.closeForm();
  }
}
