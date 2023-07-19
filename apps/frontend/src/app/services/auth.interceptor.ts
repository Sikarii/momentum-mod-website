import { Inject, Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor
} from '@angular/common/http';
import { EMPTY, Observable, throwError } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';
import { AuthService } from '@momentum/frontend/data';
import { env } from '@momentum/frontend/env';
import { DOCUMENT } from '@angular/common';

/**
 * Sets JWT access tokens on requests to the backend, and handles refresh tokens
 * whenever an access token expires.
 */
@Injectable({ providedIn: 'root' })
export class AuthInterceptor implements HttpInterceptor {
  private readonly allowedDomains = [
    'momentum-mod.org',
    new URL(env.api).host,
    new URL(env.auth).host
  ];
  private readonly standardPorts = ['80', '443'];

  private refreshInProgress: boolean;

  constructor(
    @Inject(DOCUMENT) private document: Document,
    private readonly authService: AuthService
  ) {
    this.refreshInProgress = false;
  }

  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    // We obviously don't want to do auth to any server besides our own.
    if (!this.isAllowedDomain(req)) {
      return next.handle(req);
    }

    return next.handle(req).pipe(
      catchError((error) => {
        // We only want to handle 401s (Unauthorized) which usually means the
        // access token has expired.
        if (error.status !== 401) {
          return throwError(error);
        }

        if (req.url.includes('auth/refresh')) {
          // This was called from refreshAccessToken in handleRefresh. Just let
          // the error bubble up to that subscription, where we handle the case
          // of the *refresh* token being invalid.
          return throwError(error);
        }

        // Okay, we need a new access token.
        return this.handleRefresh(req, next);
      })
    );
  }

  private handleRefresh(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    // We send several API calls on load, so if we reach this, we likely have
    // multiple requests in flight. For the first one, start call to
    // /auth/refresh, when response is received, send it to refreshTokenSubject.
    // Other requests then wait on refreshTokenSubject to emit a new token, and
    // retry.

    // First request:
    if (!this.refreshInProgress) {
      this.refreshInProgress = true;

      return this.authService.refreshAccessToken().pipe(
        // By catching the inner observable (that's returned by `next.handle`),
        // in catchError (that happened above in `intercept`) we unsubscribe to
        // it, then we wait to we get a non-null token and switchMap will
        // *resubscribe* to the inner observable, firing a new request.
        // Gotta love RxJS.
        switchMap(() => {
          this.refreshInProgress = false;
          return next.handle(req.clone());
        }),

        // The refresh token endpoint 401ed, so it's expired/invalid. Just call
        // logout to let AuthService remove our bad tokens and redirect to
        // homepage.
        //
        // For now, that'll start a new login attempt. In future, that'll put
        // user into non-logged-in mode where they can only see public pages.
        // Maybe probably not what we want - so let's determine if they *did*
        // have a token and if so start a new login session.
        catchError(() => {
          this.refreshInProgress = false;
          this.authService.logout();
          // Don't let this error bubble up, it'll mean a repeat request that is
          // certainly going to 401.
          return EMPTY;
        })
      );
    }

    // Subsequent requests:
    // Wait til valid new token is emitted, then use the
    // same `switchMap` approach to repeat.
    return next.handle(req.clone());
  }

  // Simplified version of
  // https://github.com/auth0/angular2-jwt/blob/main/projects/angular-jwt/src/lib/jwt.interceptor.ts#L51
  private isAllowedDomain(request: HttpRequest<any>): boolean {
    // `base` (second arg) handles relative URLs, is ignored for absolute
    // https://developer.mozilla.org/en-US/docs/Web/API/URL/URL#parameters
    const requestUrl = new URL(request.url, this.document.location.origin);

    // If the host equals the current window origin,
    // the domain is allowed by default
    if (requestUrl.host === this.document.location.host) {
      return true;
    }

    // If not the current domain, check the allowed list
    let hostName = requestUrl.hostname;
    if (requestUrl.port && !this.standardPorts.includes(requestUrl.port))
      hostName += `:${requestUrl.port}`;

    return this.allowedDomains.includes(hostName);
  }
}
