import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { HttpService } from './http.service';
import { JWTResponseWebDto } from '@momentum/backend/dto';

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(
    private http: HttpService,
    private router: Router
  ) {}

  public logout(): void {
    this.http.post('revoke', { type: 'auth' }).subscribe();
    localStorage.removeItem('user');

    // Redirects to frontpage for now, once we remove that from this project,
    // we've have to do an ugly `window.location.href` redirect, at least until
    // we have sections of the dashboard than can be used without a login.
    this.router.navigateByUrl('/');
  }

  public isAuthenticated(): boolean {
    const user = localStorage.getItem('user');
    return Boolean(user);
  }

  public refreshAccessToken() {
    return this.http
      .post<JWTResponseWebDto>('refresh', {
        type: 'auth',
      });
  }
}
