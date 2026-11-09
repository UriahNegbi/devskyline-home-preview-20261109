var __defProp = Object.defineProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// node_modules/@netlify/identity/dist/main.js
var main_exports = {};
__export(main_exports, {
  AUTH_EVENTS: () => AUTH_EVENTS,
  AuthError: () => AuthError,
  MissingIdentityError: () => MissingIdentityError,
  acceptInvite: () => acceptInvite,
  admin: () => admin,
  confirmEmail: () => confirmEmail,
  getIdentityConfig: () => getIdentityConfig,
  getSettings: () => getSettings,
  getUser: () => getUser,
  handleAuthCallback: () => handleAuthCallback,
  hydrateSession: () => hydrateSession,
  isAuthenticated: () => isAuthenticated,
  login: () => login,
  logout: () => logout,
  oauthLogin: () => oauthLogin,
  onAuthChange: () => onAuthChange,
  recoverPassword: () => recoverPassword,
  refreshSession: () => refreshSession,
  requestPasswordRecovery: () => requestPasswordRecovery,
  signup: () => signup,
  updateUser: () => updateUser,
  verifyEmailChange: () => verifyEmailChange,
  verifyRequestOrigin: () => verifyRequestOrigin
});

// node_modules/gotrue-js/lib/index.js
var HTTPError = class extends Error {
  constructor(response) {
    super(response.statusText);
    this.name = "HTTPError";
    this.status = response.status;
  }
};
var TextHTTPError = class extends HTTPError {
  constructor(response, data) {
    super(response);
    this.name = "TextHTTPError";
    this.data = data;
  }
};
var JSONHTTPError = class extends HTTPError {
  constructor(response, json) {
    super(response);
    this.name = "JSONHTTPError";
    this.json = json;
  }
};
var API = class _API {
  constructor(apiURL, options2) {
    this.apiURL = apiURL || "";
    this._sameOrigin = /^\/(?!\/)/.test(this.apiURL);
    this.defaultHeaders = options2?.defaultHeaders || {};
  }
  headers(headers = {}) {
    return {
      ...this.defaultHeaders,
      "Content-Type": "application/json",
      ...headers
    };
  }
  static async parseJsonResponse(response) {
    const json = await response.json();
    if (!response.ok) {
      throw new JSONHTTPError(response, json);
    }
    return json;
  }
  async request(path, options2 = {}) {
    const headers = this.headers(options2.headers || {});
    if (!options2.body) {
      delete headers["Content-Type"];
    }
    const fetchOptions = {
      ...options2,
      headers
    };
    if (this._sameOrigin) {
      fetchOptions.credentials = options2.credentials || "same-origin";
    }
    const response = await fetch(this.apiURL + path, fetchOptions);
    const contentType = response.headers.get("Content-Type");
    if (contentType?.includes("json")) {
      return _API.parseJsonResponse(response);
    }
    const data = await response.text();
    if (!response.ok) {
      throw new TextHTTPError(response, data);
    }
    return data;
  }
};
var Admin = class {
  constructor(user) {
    this.user = user;
  }
  listUsers(aud) {
    return this.user._request("/admin/users", {
      method: "GET",
      audience: aud
    });
  }
  getUser(user) {
    return this.user._request(`/admin/users/${user.id}`);
  }
  updateUser(user, attributes = {}) {
    return this.user._request(`/admin/users/${user.id}`, {
      method: "PUT",
      body: JSON.stringify(attributes)
    });
  }
  createUser(email, password, attributes = {}) {
    attributes.email = email;
    attributes.password = password;
    return this.user._request("/admin/users", {
      method: "POST",
      body: JSON.stringify(attributes)
    });
  }
  deleteUser(user) {
    return this.user._request(`/admin/users/${user.id}`, {
      method: "DELETE"
    });
  }
};
var ExpiryMargin = 60 * 1e3;
var storageKey = "gotrue.user";
var refreshPromises = {};
var currentUser = null;
var forbiddenUpdateAttributes = { api: 1, token: 1, audience: 1, url: 1 };
var forbiddenSaveAttributes = { api: 1 };
var isBrowser = () => typeof window !== "undefined";
var storageListenerActive = false;
function ensureStorageListener() {
  if (!storageListenerActive && isBrowser()) {
    storageListenerActive = true;
    window.addEventListener("storage", (event) => {
      if (event.key === storageKey) {
        currentUser = null;
      }
    });
  }
}
var User = class _User {
  constructor(api, tokenResponse, audience) {
    this.token = null;
    this.api = api;
    this.url = api.apiURL;
    this.audience = audience;
    this._processTokenResponse(tokenResponse);
    currentUser = this;
    ensureStorageListener();
  }
  static removeSavedSession() {
    isBrowser() && localStorage.removeItem(storageKey);
  }
  static recoverSession(apiInstance) {
    ensureStorageListener();
    if (currentUser) {
      return currentUser;
    }
    const json = isBrowser() && localStorage.getItem(storageKey);
    if (json) {
      try {
        const data = JSON.parse(json);
        const { url, token, audience } = data;
        if (!url || !token) {
          return null;
        }
        const api = apiInstance || new API(url, {});
        return new _User(api, token, audience)._saveUserData(data, true);
      } catch (error) {
        console.error(new Error(`Gotrue-js: Error recovering session: ${error}`));
        return null;
      }
    }
    return null;
  }
  get admin() {
    return new Admin(this);
  }
  async update(attributes) {
    const response = await this._request("/user", {
      method: "PUT",
      body: JSON.stringify(attributes)
    });
    return this._saveUserData(response)._refreshSavedSession();
  }
  jwt(forceRefresh) {
    const token = this.tokenDetails();
    if (token === null || token === void 0) {
      return Promise.reject(new Error(`Gotrue-js: failed getting jwt access token`));
    }
    const { expires_at, refresh_token, access_token } = token;
    if (forceRefresh || expires_at - ExpiryMargin < Date.now()) {
      return this._refreshToken(refresh_token);
    }
    return Promise.resolve(access_token);
  }
  logout() {
    return this._request("/logout", { method: "POST" }).then(this.clearSession.bind(this)).catch(this.clearSession.bind(this));
  }
  _refreshToken(refresh_token) {
    const existingPromise = refreshPromises[refresh_token];
    if (existingPromise) {
      return existingPromise;
    }
    const refreshRequest = this.api.request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=refresh_token&refresh_token=${refresh_token}`
    });
    const timeoutPromise = new Promise((_resolve, reject) => {
      setTimeout(() => reject(new Error("Token refresh timeout")), 3e4);
    });
    const promise = Promise.race([refreshRequest, timeoutPromise]).then((response) => {
      delete refreshPromises[refresh_token];
      this._processTokenResponse(response);
      this._refreshSavedSession();
      if (!this.token) {
        throw new Error("Gotrue-js: Token not set after refresh");
      }
      return this.token.access_token;
    }).catch((error) => {
      delete refreshPromises[refresh_token];
      this.clearSession();
      throw error;
    });
    refreshPromises[refresh_token] = promise;
    return promise;
  }
  async _request(path, options2 = {}) {
    options2.headers = options2.headers || {};
    const aud = options2.audience || this.audience;
    if (aud) {
      options2.headers["X-JWT-AUD"] = aud;
    }
    try {
      const token = await this.jwt();
      return await this.api.request(path, {
        headers: Object.assign(options2.headers, {
          Authorization: `Bearer ${token}`
        }),
        ...options2
      });
    } catch (error) {
      if (error instanceof JSONHTTPError && error.json) {
        if (error.json.msg) {
          error.message = error.json.msg;
        } else if (error.json.error) {
          error.message = `${error.json.error}: ${error.json.error_description}`;
        }
      }
      throw error;
    }
  }
  async getUserData() {
    const response = await this._request("/user");
    return this._saveUserData(response)._refreshSavedSession();
  }
  _saveUserData(attributes, fromStorage) {
    for (const key in attributes) {
      if (key in _User.prototype || key in forbiddenUpdateAttributes) {
        continue;
      }
      this[key] = attributes[key];
    }
    if (fromStorage) {
      this._fromStorage = true;
    }
    return this;
  }
  _processTokenResponse(tokenResponse) {
    this.token = tokenResponse;
    try {
      const claims = JSON.parse(urlBase64Decode(tokenResponse.access_token.split(".")[1]));
      this.token.expires_at = claims.exp * 1e3;
    } catch (error) {
      console.error(new Error(`Gotrue-js: Failed to parse tokenResponse claims: ${error}`));
    }
  }
  _refreshSavedSession() {
    if (isBrowser() && localStorage.getItem(storageKey)) {
      this._saveSession();
    }
    return this;
  }
  get _details() {
    const userCopy = {};
    for (const key in this) {
      if (key in _User.prototype || key in forbiddenSaveAttributes) {
        continue;
      }
      userCopy[key] = this[key];
    }
    return userCopy;
  }
  _saveSession() {
    isBrowser() && localStorage.setItem(storageKey, JSON.stringify(this._details));
    return this;
  }
  tokenDetails() {
    return this.token;
  }
  clearSession() {
    _User.removeSavedSession();
    this.token = null;
    currentUser = null;
  }
};
function base64Decode(base64) {
  if (typeof atob === "function") {
    return atob(base64);
  }
  return Buffer.from(base64, "base64").toString("binary");
}
function urlBase64Decode(str) {
  let output = str.replace(/-/g, "+").replace(/_/g, "/");
  switch (output.length % 4) {
    case 0:
      break;
    case 2:
      output += "==";
      break;
    case 3:
      output += "=";
      break;
    default:
      throw new Error("Illegal base64url string!");
  }
  const binaryString = base64Decode(output);
  try {
    const bytes = Uint8Array.from(binaryString, (char) => char.codePointAt(0) ?? 0);
    return new TextDecoder().decode(bytes);
  } catch {
    return binaryString;
  }
}
var HTTPRegexp = /^http:\/\//;
var defaultApiURL = `/.netlify/identity`;
var GoTrue = class {
  constructor({
    APIUrl = defaultApiURL,
    audience = "",
    setCookie = false,
    clientName = "gotrue-js"
  } = {}) {
    if (HTTPRegexp.test(APIUrl)) {
      console.warn(
        "Warning:\n\nDO NOT USE HTTP IN PRODUCTION FOR GOTRUE EVER!\nGoTrue REQUIRES HTTPS to work securely."
      );
    }
    if (audience) {
      this.audience = audience;
    }
    this.setCookie = setCookie;
    this.api = new API(APIUrl, { defaultHeaders: { "X-Nf-Client": clientName } });
  }
  async _request(path, options2 = {}) {
    options2.headers = options2.headers || {};
    const aud = options2.audience || this.audience;
    if (aud) {
      options2.headers["X-JWT-AUD"] = aud;
    }
    try {
      return await this.api.request(path, options2);
    } catch (error) {
      if (error instanceof JSONHTTPError && error.json) {
        if (error.json.msg) {
          error.message = error.json.msg;
        } else if (error.json.error) {
          error.message = `${error.json.error}: ${error.json.error_description}`;
        }
      }
      throw error;
    }
  }
  settings() {
    return this._request("/settings");
  }
  signup(email, password, data) {
    return this._request("/signup", {
      method: "POST",
      body: JSON.stringify({ email, password, data })
    });
  }
  login(email, password, remember) {
    this._setRememberHeaders(remember);
    return this._request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=password&username=${encodeURIComponent(
        email
      )}&password=${encodeURIComponent(password)}`
    }).then((response) => {
      User.removeSavedSession();
      return this.createUser(response, remember);
    });
  }
  loginExternalUrl(provider) {
    return `${this.api.apiURL}/authorize?provider=${provider}`;
  }
  confirm(token, remember) {
    this._setRememberHeaders(remember);
    return this.verify("signup", token, remember);
  }
  requestPasswordRecovery(email) {
    return this._request("/recover", {
      method: "POST",
      body: JSON.stringify({ email })
    });
  }
  recover(token, remember) {
    this._setRememberHeaders(remember);
    return this.verify("recovery", token, remember);
  }
  acceptInvite(token, password, remember) {
    this._setRememberHeaders(remember);
    return this._request("/verify", {
      method: "POST",
      body: JSON.stringify({ token, password, type: "signup" })
    }).then((response) => this.createUser(response, remember));
  }
  acceptInviteExternalUrl(provider, token) {
    return `${this.api.apiURL}/authorize?provider=${provider}&invite_token=${token}`;
  }
  createUser(tokenResponse, remember = false) {
    this._setRememberHeaders(remember);
    const user = new User(this.api, tokenResponse, this.audience || "");
    return user.getUserData().then((userData) => {
      if (remember) {
        userData._saveSession();
      }
      return userData;
    });
  }
  currentUser() {
    const user = User.recoverSession(this.api);
    user && this._setRememberHeaders(user._fromStorage);
    return user;
  }
  async validateCurrentSession() {
    const user = this.currentUser();
    if (!user) {
      return null;
    }
    try {
      return await user.getUserData();
    } catch {
      user.clearSession();
      return null;
    }
  }
  verify(type, token, remember) {
    this._setRememberHeaders(remember);
    return this._request("/verify", {
      method: "POST",
      body: JSON.stringify({ token, type })
    }).then((response) => this.createUser(response, remember));
  }
  _setRememberHeaders(remember) {
    if (this.setCookie) {
      this.api.defaultHeaders = this.api.defaultHeaders || {};
      this.api.defaultHeaders["X-Use-Cookie"] = remember ? "1" : "session";
    }
  }
};
if (typeof window !== "undefined") {
  window.GoTrue = GoTrue;
}

// node_modules/@netlify/identity/dist/main.js
var __require2 = /* @__PURE__ */ ((x) => typeof __require !== "undefined" ? __require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof __require !== "undefined" ? __require : a)[b]
}) : x)(function(x) {
  if (typeof __require !== "undefined") return __require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var AUTH_PROVIDERS = ["google", "github", "gitlab", "bitbucket", "facebook", "email"];
var AuthError = class _AuthError extends Error {
  constructor(message, status, options2) {
    super(message);
    this.name = "AuthError";
    this.status = status;
    if (options2 && "cause" in options2) {
      this.cause = options2.cause;
    }
  }
  static from(error) {
    if (error instanceof _AuthError) return error;
    const message = error instanceof Error ? error.message : String(error);
    return new _AuthError(message, void 0, { cause: error });
  }
};
var MissingIdentityError = class extends Error {
  constructor(message = "Netlify Identity is not available.") {
    super(message);
    this.name = "MissingIdentityError";
  }
};
var IDENTITY_PATH = "/.netlify/identity";
var goTrueClient = null;
var cachedApiUrl;
var warnedMissingUrl = false;
var isBrowser2 = () => typeof window !== "undefined" && typeof window.location !== "undefined";
var discoverApiUrl = () => {
  if (cachedApiUrl !== void 0) return cachedApiUrl;
  if (isBrowser2()) {
    cachedApiUrl = `${window.location.origin}${IDENTITY_PATH}`;
  } else {
    const identityContext = getIdentityContext();
    if (identityContext?.url) {
      cachedApiUrl = identityContext.url;
    } else if (globalThis.Netlify?.context?.url) {
      cachedApiUrl = new URL(IDENTITY_PATH, globalThis.Netlify.context.url).href;
    } else if (typeof process !== "undefined" && process.env?.URL) {
      cachedApiUrl = new URL(IDENTITY_PATH, process.env.URL).href;
    }
  }
  return cachedApiUrl ?? null;
};
var getGoTrueClient = () => {
  if (goTrueClient) return goTrueClient;
  const apiUrl = discoverApiUrl();
  if (!apiUrl) {
    if (!warnedMissingUrl) {
      console.warn(
        "@netlify/identity: Could not determine the Identity endpoint URL. Make sure your site has Netlify Identity enabled, or run your app with `netlify dev`."
      );
      warnedMissingUrl = true;
    }
    return null;
  }
  goTrueClient = new GoTrue({ APIUrl: apiUrl, setCookie: false });
  return goTrueClient;
};
var getClient = () => {
  const client = getGoTrueClient();
  if (!client) throw new MissingIdentityError();
  return client;
};
var getIdentityContext = () => {
  const identityContext = globalThis.netlifyIdentityContext;
  if (identityContext?.url) {
    return {
      url: identityContext.url,
      token: identityContext.token
    };
  }
  if (globalThis.Netlify?.context?.url) {
    return { url: new URL(IDENTITY_PATH, globalThis.Netlify.context.url).href };
  }
  const siteUrl = typeof process !== "undefined" ? process.env?.URL : void 0;
  if (siteUrl) {
    return { url: new URL(IDENTITY_PATH, siteUrl).href };
  }
  return null;
};
var NF_JWT_COOKIE = "nf_jwt";
var NF_REFRESH_COOKIE = "nf_refresh";
var getCookie = (name) => {
  if (typeof document === "undefined") return null;
  const match = new RegExp(`(?:^|; )${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=([^;]*)`).exec(document.cookie);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
};
var setAuthCookies = (cookies, accessToken, refreshToken) => {
  cookies.set({
    name: NF_JWT_COOKIE,
    value: accessToken,
    httpOnly: false,
    secure: true,
    path: "/",
    sameSite: "Lax"
  });
  if (refreshToken) {
    cookies.set({
      name: NF_REFRESH_COOKIE,
      value: refreshToken,
      httpOnly: false,
      secure: true,
      path: "/",
      sameSite: "Lax"
    });
  }
};
var deleteAuthCookies = (cookies) => {
  cookies.delete(NF_JWT_COOKIE);
  cookies.delete(NF_REFRESH_COOKIE);
};
var setBrowserAuthCookies = (accessToken, refreshToken) => {
  if (typeof document === "undefined") return;
  document.cookie = `${NF_JWT_COOKIE}=${encodeURIComponent(accessToken)}; path=/; secure; samesite=lax`;
  if (refreshToken) {
    document.cookie = `${NF_REFRESH_COOKIE}=${encodeURIComponent(refreshToken)}; path=/; secure; samesite=lax`;
  }
};
var deleteBrowserAuthCookies = () => {
  if (typeof document === "undefined") return;
  document.cookie = `${NF_JWT_COOKIE}=; path=/; secure; samesite=lax; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  document.cookie = `${NF_REFRESH_COOKIE}=; path=/; secure; samesite=lax; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
};
var getServerCookie = (name) => {
  const cookies = globalThis.Netlify?.context?.cookies;
  if (!cookies || typeof cookies.get !== "function") return null;
  return cookies.get(name) ?? null;
};
var nextHeadersFn;
var triggerNextjsDynamic = () => {
  if (nextHeadersFn === null) return;
  if (nextHeadersFn === void 0) {
    try {
      if (typeof __require2 === "undefined") {
        nextHeadersFn = null;
        return;
      }
      const mod = __require2("next/headers");
      nextHeadersFn = mod.headers;
    } catch {
      nextHeadersFn = null;
      return;
    }
  }
  const fn = nextHeadersFn;
  if (!fn) return;
  try {
    fn();
  } catch (e) {
    if (e instanceof Error && ("digest" in e || /bail\s*out.*prerende/i.test(e.message))) {
      throw e;
    }
  }
};
var DEFAULT_TIMEOUT_MS = 5e3;
var fetchWithTimeout = async (url, options2 = {}, timeoutMs = DEFAULT_TIMEOUT_MS) => {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, timeoutMs);
  try {
    return await fetch(url, { ...options2, signal: controller.signal });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      const pathname = new URL(url).pathname;
      throw new AuthError(`Identity request to ${pathname} timed out after ${String(timeoutMs)}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
};
var AUTH_EVENTS = {
  LOGIN: "login",
  LOGOUT: "logout",
  TOKEN_REFRESH: "token_refresh",
  USER_UPDATED: "user_updated",
  RECOVERY: "recovery"
};
var GOTRUE_STORAGE_KEY = "gotrue.user";
var listeners = /* @__PURE__ */ new Set();
var emitAuthEvent = (event, user) => {
  for (const listener of listeners) {
    try {
      listener(event, user);
    } catch {
    }
  }
};
var storageListenerAttached = false;
var attachStorageListener = () => {
  if (storageListenerAttached || !isBrowser2()) return;
  storageListenerAttached = true;
  window.addEventListener("storage", (event) => {
    if (event.key !== GOTRUE_STORAGE_KEY) return;
    if (event.newValue) {
      const client = getGoTrueClient();
      const currentUser2 = client?.currentUser();
      emitAuthEvent(AUTH_EVENTS.LOGIN, currentUser2 ? toUser(currentUser2) : null);
    } else {
      emitAuthEvent(AUTH_EVENTS.LOGOUT, null);
    }
  });
};
var onAuthChange = (callback) => {
  if (!isBrowser2()) {
    return () => {
    };
  }
  listeners.add(callback);
  attachStorageListener();
  return () => {
    listeners.delete(callback);
  };
};
var REFRESH_MARGIN_S = 60;
var refreshTimer = null;
var startTokenRefresh = () => {
  if (!isBrowser2()) return;
  stopTokenRefresh();
  const client = getGoTrueClient();
  const user = client?.currentUser();
  if (!user) return;
  const token = user.tokenDetails();
  if (!token?.expires_at) return;
  const nowS = Math.floor(Date.now() / 1e3);
  const expiresAtS = typeof token.expires_at === "number" && token.expires_at > 1e12 ? Math.floor(token.expires_at / 1e3) : token.expires_at;
  const delayMs = Math.max(0, expiresAtS - nowS - REFRESH_MARGIN_S) * 1e3;
  refreshTimer = setTimeout(() => {
    void (async () => {
      try {
        const freshJwt = await user.jwt(true);
        const freshDetails = user.tokenDetails();
        setBrowserAuthCookies(freshJwt, freshDetails?.refresh_token);
        emitAuthEvent(AUTH_EVENTS.TOKEN_REFRESH, toUser(user));
        startTokenRefresh();
      } catch {
        stopTokenRefresh();
      }
    })();
  }, delayMs);
};
var stopTokenRefresh = () => {
  if (refreshTimer !== null) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
};
var refreshSession = async () => {
  if (isBrowser2()) {
    const client = getGoTrueClient();
    const user = client?.currentUser();
    if (!user) return null;
    const details = user.tokenDetails();
    if (details?.expires_at) {
      const nowS2 = Math.floor(Date.now() / 1e3);
      const expiresAtS = typeof details.expires_at === "number" && details.expires_at > 1e12 ? Math.floor(details.expires_at / 1e3) : details.expires_at;
      if (expiresAtS - nowS2 > REFRESH_MARGIN_S) {
        return null;
      }
    }
    try {
      const jwt = await user.jwt(true);
      setBrowserAuthCookies(jwt, user.tokenDetails()?.refresh_token);
      emitAuthEvent(AUTH_EVENTS.TOKEN_REFRESH, toUser(user));
      startTokenRefresh();
      return jwt;
    } catch {
      stopTokenRefresh();
      return null;
    }
  }
  const accessToken = getServerCookie(NF_JWT_COOKIE);
  const refreshToken = getServerCookie(NF_REFRESH_COOKIE);
  if (!accessToken || !refreshToken) return null;
  const decoded = decodeJwtPayload(accessToken);
  if (!decoded?.exp) return null;
  const nowS = Math.floor(Date.now() / 1e3);
  if (decoded.exp - nowS > REFRESH_MARGIN_S) {
    return null;
  }
  const ctx = getIdentityContext();
  const identityUrl = ctx?.url ?? (globalThis.Netlify?.context?.url ? new URL(IDENTITY_PATH, globalThis.Netlify.context.url).href : null);
  if (!identityUrl) {
    throw new AuthError("Could not determine the Identity endpoint URL for token refresh");
  }
  let res;
  try {
    res = await fetchWithTimeout(`${identityUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }).toString()
    });
  } catch (error) {
    throw AuthError.from(error);
  }
  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({}));
    if (res.status === 401 || res.status === 400) {
      const cookies2 = globalThis.Netlify?.context?.cookies;
      if (cookies2) {
        deleteAuthCookies(cookies2);
      }
      return null;
    }
    throw new AuthError(errorBody.msg ?? `Token refresh failed (${String(res.status)})`, res.status);
  }
  const data = await res.json();
  const cookies = globalThis.Netlify?.context?.cookies;
  if (cookies) {
    setAuthCookies(cookies, data.access_token, data.refresh_token);
  }
  return data.access_token;
};
var getCookies = () => {
  const cookies = globalThis.Netlify?.context?.cookies;
  if (!cookies) {
    throw new AuthError("Server-side auth requires Netlify Functions runtime");
  }
  return cookies;
};
var getServerIdentityUrl = () => {
  const ctx = getIdentityContext();
  if (!ctx?.url) {
    throw new AuthError("Could not determine the Identity endpoint URL on the server");
  }
  return ctx.url;
};
var persistSession = true;
var login = async (email, password) => {
  if (!isBrowser2()) {
    const identityUrl = getServerIdentityUrl();
    const cookies = getCookies();
    const body = new URLSearchParams({
      grant_type: "password",
      username: email,
      password
    });
    let res;
    try {
      res = await fetchWithTimeout(`${identityUrl}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString()
      });
    } catch (error) {
      throw AuthError.from(error);
    }
    if (!res.ok) {
      const errorBody = await res.json().catch(() => ({}));
      throw new AuthError(
        errorBody.msg ?? errorBody.error_description ?? `Login failed (${String(res.status)})`,
        res.status
      );
    }
    const data = await res.json();
    const accessToken = data.access_token;
    let userRes;
    try {
      userRes = await fetchWithTimeout(`${identityUrl}/user`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
    } catch (error) {
      throw AuthError.from(error);
    }
    if (!userRes.ok) {
      const errorBody = await userRes.json().catch(() => ({}));
      throw new AuthError(errorBody.msg ?? `Failed to fetch user data (${String(userRes.status)})`, userRes.status);
    }
    const userData = await userRes.json();
    const user = toUser(userData);
    setAuthCookies(cookies, accessToken, data.refresh_token);
    return user;
  }
  const client = getClient();
  try {
    const gotrueUser = await client.login(email, password, persistSession);
    const jwt = await gotrueUser.jwt();
    setBrowserAuthCookies(jwt, gotrueUser.tokenDetails()?.refresh_token);
    const user = toUser(gotrueUser);
    startTokenRefresh();
    emitAuthEvent(AUTH_EVENTS.LOGIN, user);
    return user;
  } catch (error) {
    throw AuthError.from(error);
  }
};
var signup = async (email, password, data) => {
  if (!isBrowser2()) {
    const identityUrl = getServerIdentityUrl();
    const cookies = getCookies();
    let res;
    try {
      res = await fetchWithTimeout(`${identityUrl}/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, data })
      });
    } catch (error) {
      throw AuthError.from(error);
    }
    if (!res.ok) {
      const errorBody = await res.json().catch(() => ({}));
      throw new AuthError(errorBody.msg ?? `Signup failed (${String(res.status)})`, res.status);
    }
    const responseData = await res.json();
    const user = toUser(responseData);
    if (responseData.confirmed_at) {
      const accessToken = responseData.access_token;
      if (accessToken) {
        setAuthCookies(cookies, accessToken, responseData.refresh_token);
      }
    }
    return user;
  }
  const client = getClient();
  try {
    const response = await client.signup(email, password, data);
    const user = toUser(response);
    if (response.confirmed_at) {
      const jwt = await response.jwt?.();
      if (jwt) {
        const refreshToken = response.tokenDetails?.()?.refresh_token;
        setBrowserAuthCookies(jwt, refreshToken);
      }
      startTokenRefresh();
      emitAuthEvent(AUTH_EVENTS.LOGIN, user);
    }
    return user;
  } catch (error) {
    throw AuthError.from(error);
  }
};
var logout = async () => {
  if (!isBrowser2()) {
    const identityUrl = getServerIdentityUrl();
    const cookies = getCookies();
    const jwt = cookies.get(NF_JWT_COOKIE);
    if (jwt) {
      try {
        await fetchWithTimeout(`${identityUrl}/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${jwt}` }
        });
      } catch {
      }
    }
    deleteAuthCookies(cookies);
    return;
  }
  const client = getClient();
  try {
    const currentUser2 = client.currentUser();
    if (currentUser2) {
      await currentUser2.logout();
    }
    deleteBrowserAuthCookies();
    stopTokenRefresh();
    emitAuthEvent(AUTH_EVENTS.LOGOUT, null);
  } catch (error) {
    throw AuthError.from(error);
  }
};
var oauthLogin = (provider) => {
  if (!isBrowser2()) {
    throw new AuthError("oauthLogin() is only available in the browser");
  }
  const client = getClient();
  window.location.href = client.loginExternalUrl(provider);
  throw new AuthError("Redirecting to OAuth provider");
};
var handleAuthCallback = async () => {
  if (!isBrowser2()) return null;
  const hash = window.location.hash.substring(1);
  if (!hash) return null;
  const client = getClient();
  const params = new URLSearchParams(hash);
  try {
    const accessToken = params.get("access_token");
    if (accessToken) return await handleOAuthCallback(client, params, accessToken);
    const confirmationToken = params.get("confirmation_token");
    if (confirmationToken) return await handleConfirmationCallback(client, confirmationToken);
    const recoveryToken = params.get("recovery_token");
    if (recoveryToken) return await handleRecoveryCallback(client, recoveryToken);
    const inviteToken = params.get("invite_token");
    if (inviteToken) return handleInviteCallback(inviteToken);
    const emailChangeToken = params.get("email_change_token");
    if (emailChangeToken) return await handleEmailChangeCallback(client, emailChangeToken);
    return null;
  } catch (error) {
    if (error instanceof AuthError) throw error;
    throw AuthError.from(error);
  }
};
var handleOAuthCallback = async (client, params, accessToken) => {
  const refreshToken = params.get("refresh_token") ?? "";
  const expiresIn = parseInt(params.get("expires_in") ?? "", 10);
  const expiresAt = parseInt(params.get("expires_at") ?? "", 10);
  const gotrueUser = await client.createUser(
    {
      access_token: accessToken,
      token_type: params.get("token_type") ?? "bearer",
      expires_in: isFinite(expiresIn) ? expiresIn : 3600,
      expires_at: isFinite(expiresAt) ? expiresAt : Math.floor(Date.now() / 1e3) + 3600,
      refresh_token: refreshToken
    },
    persistSession
  );
  setBrowserAuthCookies(accessToken, refreshToken || void 0);
  const user = toUser(gotrueUser);
  startTokenRefresh();
  clearHash();
  emitAuthEvent(AUTH_EVENTS.LOGIN, user);
  return { type: "oauth", user };
};
var handleConfirmationCallback = async (client, token) => {
  const gotrueUser = await client.confirm(token, persistSession);
  const jwt = await gotrueUser.jwt();
  setBrowserAuthCookies(jwt, gotrueUser.tokenDetails()?.refresh_token);
  const user = toUser(gotrueUser);
  startTokenRefresh();
  clearHash();
  emitAuthEvent(AUTH_EVENTS.LOGIN, user);
  return { type: "confirmation", user };
};
var handleRecoveryCallback = async (client, token) => {
  const gotrueUser = await client.recover(token, persistSession);
  const jwt = await gotrueUser.jwt();
  setBrowserAuthCookies(jwt, gotrueUser.tokenDetails()?.refresh_token);
  const user = toUser(gotrueUser);
  startTokenRefresh();
  clearHash();
  emitAuthEvent(AUTH_EVENTS.RECOVERY, user);
  return { type: "recovery", user };
};
var handleInviteCallback = (token) => {
  clearHash();
  return { type: "invite", user: null, token };
};
var handleEmailChangeCallback = async (client, emailChangeToken) => {
  const currentUser2 = client.currentUser();
  if (!currentUser2) {
    throw new AuthError("Email change verification requires an active browser session");
  }
  const jwt = await currentUser2.jwt();
  const identityUrl = `${window.location.origin}${IDENTITY_PATH}`;
  const emailChangeRes = await fetch(`${identityUrl}/user`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`
    },
    body: JSON.stringify({ email_change_token: emailChangeToken })
  });
  if (!emailChangeRes.ok) {
    const errorBody = await emailChangeRes.json().catch(() => ({}));
    throw new AuthError(
      errorBody.msg ?? `Email change verification failed (${String(emailChangeRes.status)})`,
      emailChangeRes.status
    );
  }
  const emailChangeData = await emailChangeRes.json();
  const user = toUser(emailChangeData);
  clearHash();
  emitAuthEvent(AUTH_EVENTS.USER_UPDATED, user);
  return { type: "email_change", user };
};
var clearHash = () => {
  history.replaceState(null, "", window.location.pathname + window.location.search);
};
var hydrateSession = async () => {
  if (!isBrowser2()) return null;
  const client = getClient();
  const currentUser2 = client.currentUser();
  if (currentUser2) {
    startTokenRefresh();
    return toUser(currentUser2);
  }
  const accessToken = getCookie(NF_JWT_COOKIE);
  if (!accessToken) return null;
  const refreshToken = getCookie(NF_REFRESH_COOKIE) ?? "";
  const decoded = decodeJwtPayload(accessToken);
  const expiresAt = decoded?.exp ?? Math.floor(Date.now() / 1e3) + 3600;
  const expiresIn = Math.max(0, expiresAt - Math.floor(Date.now() / 1e3));
  let gotrueUser;
  try {
    gotrueUser = await client.createUser(
      {
        access_token: accessToken,
        token_type: "bearer",
        expires_in: expiresIn,
        expires_at: expiresAt,
        refresh_token: refreshToken
      },
      persistSession
    );
  } catch {
    deleteBrowserAuthCookies();
    return null;
  }
  const user = toUser(gotrueUser);
  startTokenRefresh();
  emitAuthEvent(AUTH_EVENTS.LOGIN, user);
  return user;
};
var toAuthProvider = (value) => typeof value === "string" && AUTH_PROVIDERS.includes(value) ? value : void 0;
var toOptionalString = (value) => typeof value === "string" && value !== "" ? value : void 0;
var toRoles = (appMeta) => {
  const roles = appMeta.roles;
  if (Array.isArray(roles) && roles.every((r) => typeof r === "string")) {
    return roles;
  }
  return void 0;
};
var toUser = (userData) => {
  const userMeta = userData.user_metadata ?? {};
  const appMeta = userData.app_metadata ?? {};
  const name = userMeta.full_name ?? userMeta.name;
  const pictureUrl = userMeta.avatar_url;
  return {
    id: userData.id,
    email: userData.email,
    confirmedAt: toOptionalString(userData.confirmed_at),
    createdAt: userData.created_at,
    updatedAt: userData.updated_at,
    role: toOptionalString(userData.role),
    provider: toAuthProvider(appMeta.provider),
    name: typeof name === "string" ? name : void 0,
    pictureUrl: typeof pictureUrl === "string" ? pictureUrl : void 0,
    roles: toRoles(appMeta),
    invitedAt: toOptionalString(userData.invited_at),
    confirmationSentAt: toOptionalString(userData.confirmation_sent_at),
    recoverySentAt: toOptionalString(userData.recovery_sent_at),
    pendingEmail: toOptionalString(userData.new_email),
    emailChangeSentAt: toOptionalString(userData.email_change_sent_at),
    lastSignInAt: toOptionalString(userData.last_sign_in_at),
    userMetadata: userMeta,
    appMetadata: appMeta
  };
};
var claimsToUser = (claims) => {
  const appMeta = claims.app_metadata ?? {};
  const userMeta = claims.user_metadata ?? {};
  const name = userMeta.full_name ?? userMeta.name;
  const pictureUrl = userMeta.avatar_url;
  return {
    id: claims.sub ?? "",
    email: claims.email,
    provider: toAuthProvider(appMeta.provider),
    name: typeof name === "string" ? name : void 0,
    pictureUrl: typeof pictureUrl === "string" ? pictureUrl : void 0,
    roles: toRoles(appMeta),
    userMetadata: userMeta,
    appMetadata: appMeta
  };
};
var decodeJwtPayload = (token) => {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(payload);
  } catch {
    return null;
  }
};
var fetchFullUser = async (identityUrl, jwt) => {
  try {
    const res = await fetchWithTimeout(`${identityUrl}/user`, {
      headers: { Authorization: `Bearer ${jwt}` }
    });
    if (!res.ok) return null;
    const userData = await res.json();
    return toUser(userData);
  } catch {
    return null;
  }
};
var resolveIdentityUrl = () => {
  const identityContext = getIdentityContext();
  if (identityContext?.url) return identityContext.url;
  if (globalThis.Netlify?.context?.url) {
    return new URL(IDENTITY_PATH, globalThis.Netlify.context.url).href;
  }
  const siteUrl = typeof process !== "undefined" ? process.env?.URL : void 0;
  if (siteUrl) {
    return new URL(IDENTITY_PATH, siteUrl).href;
  }
  return null;
};
var getUser = async () => {
  if (isBrowser2()) {
    const client = getGoTrueClient();
    const currentUser2 = client?.currentUser() ?? null;
    if (currentUser2) {
      const jwt2 = getCookie(NF_JWT_COOKIE);
      if (!jwt2) {
        try {
          currentUser2.clearSession();
        } catch {
        }
        return null;
      }
      startTokenRefresh();
      return toUser(currentUser2);
    }
    const jwt = getCookie(NF_JWT_COOKIE);
    if (!jwt) return null;
    const claims2 = decodeJwtPayload(jwt);
    if (!claims2) return null;
    const hydrated = await hydrateSession();
    return hydrated ?? null;
  }
  triggerNextjsDynamic();
  const identityContext = globalThis.netlifyIdentityContext;
  const serverJwt = identityContext?.token ?? getServerCookie(NF_JWT_COOKIE);
  if (serverJwt) {
    const identityUrl = resolveIdentityUrl();
    if (identityUrl) {
      const fullUser = await fetchFullUser(identityUrl, serverJwt);
      if (fullUser) return fullUser;
    }
  }
  const claims = identityContext?.user ?? null;
  return claims ? claimsToUser(claims) : null;
};
var isAuthenticated = async () => await getUser() !== null;
var getIdentityConfig = () => {
  if (isBrowser2()) {
    return { url: `${window.location.origin}${IDENTITY_PATH}` };
  }
  return getIdentityContext();
};
var getSettings = async () => {
  const client = getClient();
  try {
    const raw = await client.settings();
    const external = raw.external ?? {};
    return {
      autoconfirm: raw.autoconfirm,
      disableSignup: raw.disable_signup,
      providers: {
        google: external.google ?? false,
        github: external.github ?? false,
        gitlab: external.gitlab ?? false,
        bitbucket: external.bitbucket ?? false,
        facebook: external.facebook ?? false,
        email: external.email ?? false
      }
    };
  } catch (err) {
    throw new AuthError(err instanceof Error ? err.message : "Failed to fetch identity settings", 502, { cause: err });
  }
};
var verifyRequestOrigin = (request, options2) => {
  const origin = request.headers.get("origin");
  if (!origin) {
    throw new AuthError("Cross-origin request refused: missing Origin header.", 403);
  }
  const allowed = options2?.allowedOrigins ?? [new URL(request.url).origin];
  if (!allowed.includes(origin)) {
    throw new AuthError(`Cross-origin request refused: Origin ${origin} did not match an allowed origin.`, 403);
  }
};
var resolveCurrentUser = async () => {
  const client = getClient();
  let currentUser2 = client.currentUser();
  if (!currentUser2 && isBrowser2()) {
    try {
      await hydrateSession();
    } catch {
    }
    currentUser2 = client.currentUser();
  }
  if (!currentUser2) throw new AuthError("No user is currently logged in");
  return currentUser2;
};
var requestPasswordRecovery = async (email) => {
  const client = getClient();
  try {
    await client.requestPasswordRecovery(email);
  } catch (error) {
    throw AuthError.from(error);
  }
};
var recoverPassword = async (token, newPassword) => {
  const client = getClient();
  try {
    const gotrueUser = await client.recover(token, persistSession);
    const updatedUser = await gotrueUser.update({ password: newPassword });
    const user = toUser(updatedUser);
    startTokenRefresh();
    emitAuthEvent(AUTH_EVENTS.LOGIN, user);
    return user;
  } catch (error) {
    throw AuthError.from(error);
  }
};
var confirmEmail = async (token) => {
  const client = getClient();
  try {
    const gotrueUser = await client.confirm(token, persistSession);
    const user = toUser(gotrueUser);
    startTokenRefresh();
    emitAuthEvent(AUTH_EVENTS.LOGIN, user);
    return user;
  } catch (error) {
    throw AuthError.from(error);
  }
};
var acceptInvite = async (token, password) => {
  const client = getClient();
  try {
    const gotrueUser = await client.acceptInvite(token, password, persistSession);
    const user = toUser(gotrueUser);
    startTokenRefresh();
    emitAuthEvent(AUTH_EVENTS.LOGIN, user);
    return user;
  } catch (error) {
    throw AuthError.from(error);
  }
};
var verifyEmailChange = async (token) => {
  if (!isBrowser2()) throw new AuthError("verifyEmailChange() is only available in the browser");
  const currentUser2 = await resolveCurrentUser();
  try {
    const jwt = await currentUser2.jwt();
    const identityUrl = `${window.location.origin}${IDENTITY_PATH}`;
    const res = await fetch(`${identityUrl}/user`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${jwt}`
      },
      body: JSON.stringify({ email_change_token: token })
    });
    if (!res.ok) {
      const errorBody = await res.json().catch(() => ({}));
      throw new AuthError(errorBody.msg ?? `Email change verification failed (${String(res.status)})`, res.status);
    }
    const userData = await res.json();
    const user = toUser(userData);
    emitAuthEvent(AUTH_EVENTS.USER_UPDATED, user);
    return user;
  } catch (error) {
    if (error instanceof AuthError) throw error;
    throw AuthError.from(error);
  }
};
var updateUser = async (updates) => {
  const currentUser2 = await resolveCurrentUser();
  try {
    const updatedUser = await currentUser2.update(updates);
    const user = toUser(updatedUser);
    emitAuthEvent(AUTH_EVENTS.USER_UPDATED, user);
    return user;
  } catch (error) {
    throw AuthError.from(error);
  }
};
var SERVER_ONLY_MESSAGE = "Admin operations are server-only. Call admin methods from a Netlify Function or Edge Function, not from browser code.";
var sanitizeUserId = (userId) => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(userId)) {
    throw new AuthError("User ID is not a valid UUID");
  }
  return encodeURIComponent(userId);
};
var assertServer = () => {
  if (isBrowser2()) {
    throw new AuthError(SERVER_ONLY_MESSAGE);
  }
};
var getAdminAuth = () => {
  const ctx = getIdentityContext();
  if (!ctx?.url) {
    throw new AuthError("Could not determine the Identity endpoint URL on the server");
  }
  if (!ctx.token) {
    throw new AuthError("Admin operations require an operator token (only available in Netlify Functions)");
  }
  return { url: ctx.url, token: ctx.token };
};
var adminFetch = async (path, options2 = {}) => {
  const { url, token } = getAdminAuth();
  let res;
  try {
    res = await fetchWithTimeout(`${url}${path}`, {
      ...options2,
      headers: {
        ...options2.headers,
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    });
  } catch (error) {
    throw new AuthError(error.message, void 0, { cause: error });
  }
  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({}));
    throw new AuthError(
      errorBody.msg ?? `Admin request failed (${String(res.status)})`,
      res.status
    );
  }
  return res;
};
var listUsers = async (options2) => {
  assertServer();
  const params = new URLSearchParams();
  if (options2?.page != null) params.set("page", String(options2.page));
  if (options2?.perPage != null) params.set("per_page", String(options2.perPage));
  const query = params.toString();
  const path = `/admin/users${query ? `?${query}` : ""}`;
  const res = await adminFetch(path);
  const body = await res.json();
  return body.users.map(toUser);
};
var getUser2 = async (userId) => {
  assertServer();
  const sanitizedUserId = sanitizeUserId(userId);
  const res = await adminFetch(`/admin/users/${sanitizedUserId}`);
  const userData = await res.json();
  return toUser(userData);
};
var createUser = async (params) => {
  assertServer();
  const body = {
    email: params.email,
    password: params.password,
    confirm: true
  };
  if (params.data) {
    const allowedKeys = ["role", "app_metadata", "user_metadata"];
    for (const key of allowedKeys) {
      if (key in params.data) {
        body[key] = params.data[key];
      }
    }
  }
  const res = await adminFetch("/admin/users", {
    method: "POST",
    body: JSON.stringify(body)
  });
  const userData = await res.json();
  return toUser(userData);
};
var updateUser2 = async (userId, attributes) => {
  assertServer();
  const sanitizedUserId = sanitizeUserId(userId);
  const body = {};
  const allowedKeys = ["email", "password", "role", "confirm", "app_metadata", "user_metadata"];
  for (const key of allowedKeys) {
    if (key in attributes) {
      body[key] = attributes[key];
    }
  }
  const res = await adminFetch(`/admin/users/${sanitizedUserId}`, {
    method: "PUT",
    body: JSON.stringify(body)
  });
  const userData = await res.json();
  return toUser(userData);
};
var deleteUser = async (userId) => {
  assertServer();
  const sanitizedUserId = sanitizeUserId(userId);
  await adminFetch(`/admin/users/${sanitizedUserId}`, { method: "DELETE" });
};
var admin = { listUsers, getUser: getUser2, createUser, updateUser: updateUser2, deleteUser };

// src/admin/ui.js
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}
var projectStages = [
  ["discovery", "\u05D4\u05D9\u05DB\u05E8\u05D5\u05EA"],
  ["planning", "\u05EA\u05DB\u05E0\u05D5\u05DF"],
  ["design", "\u05E2\u05D9\u05E6\u05D5\u05D1"],
  ["development", "\u05E4\u05D9\u05EA\u05D5\u05D7"],
  ["review", "\u05D1\u05D3\u05D9\u05E7\u05D5\u05EA"],
  ["launched", "\u05D1\u05D0\u05D5\u05D5\u05D9\u05E8"],
  ["on_hold", "\u05D1\u05D4\u05DE\u05EA\u05E0\u05D4"]
];
var leadStages = [["new", "\u05D7\u05D3\u05E9"], ["contacted", "\u05E0\u05D5\u05E6\u05E8 \u05E7\u05E9\u05E8"], ["proposal", "\u05D4\u05E6\u05E2\u05D4"], ["won", "\u05E0\u05E1\u05D2\u05E8"], ["lost", "\u05DC\u05D0 \u05D4\u05EA\u05E7\u05D3\u05DD"]];
var roleNames = { owner: "\u05D1\u05E2\u05DC\u05D9\u05DD", admin: "\u05DE\u05E0\u05D4\u05DC/\u05EA", developer: "\u05DE\u05E4\u05EA\u05D7/\u05EA", viewer: "\u05E6\u05E4\u05D9\u05D9\u05D4 \u05D1\u05DC\u05D1\u05D3" };
var knownStatuses = new Set([...projectStages, ...leadStages].map(([key]) => key));
var moneyLabel = (amount) => new Intl.NumberFormat("he-IL", { style: "currency", currency: "ILS", maximumFractionDigits: 2 }).format(Number(amount || 0));
var shekel = (amount) => new Intl.NumberFormat("he-IL", { style: "currency", currency: "ILS", maximumFractionDigits: 0 }).format(amount);
var options = (rows, selected = "") => rows.map(([value, label2]) => `<option value="${escapeHtml(value)}" ${String(value) === String(selected) ? "selected" : ""}>${escapeHtml(label2)}</option>`).join("");
var stageName = (rows, value) => rows.find(([key]) => key === value)?.[1] || String(value || "");
var roleName = (role) => roleNames[role] || String(role || "");
function leadStageLabel(lead) {
  if (lead?.source === "voice_callback" && lead.status === "new") return "\u05DE\u05DE\u05EA\u05D9\u05DF \u05DC\u05D8\u05D9\u05E4\u05D5\u05DC \u05D0\u05E0\u05D5\u05E9\u05D9";
  return stageName(leadStages, lead.status);
}
function callbackSection(leads, canManage) {
  const rows = leads.filter((lead) => lead.source === "voice_callback");
  const list = rows.length ? rows.map((lead) => `<article class="workspace-row callback-row"><div><b>${escapeHtml(lead.name)}</b>${chip(lead.status, leadStageLabel(lead))}<span dir="ltr">${escapeHtml(lead.contact)}</span><p class="callback-copy">${escapeHtml(lead.message || "")}</p></div>${canManage ? `<label>\u05E9\u05DC\u05D1<select class="lead-status" data-id="${escapeHtml(lead.id)}">${options(leadStages, lead.status)}</select></label>` : chip(lead.status, leadStageLabel(lead))}</article>`).join("") : '<p class="workspace-empty">\u05D0\u05D9\u05DF \u05D1\u05E7\u05E9\u05D5\u05EA \u05E9\u05D9\u05D7\u05D4 \u05D7\u05D5\u05D6\u05E8\u05EA.</p>';
  return `<section class="workspace-section" id="callbacks"><div class="workspace-heading"><div><span>CALLBACKS</span><h2>\u05D1\u05E7\u05E9\u05D5\u05EA \u05E9\u05D9\u05D7\u05D4 \u05D7\u05D5\u05D6\u05E8\u05EA</h2><p>\u05E0\u05E8\u05E9\u05DD \u05DB\u05D1\u05E7\u05E9\u05D4 \u05DC\u05E9\u05D9\u05D7\u05D4 \u05D0\u05E0\u05D5\u05E9\u05D9\u05EA. \u05DC\u05D0 \u05D1\u05D5\u05E6\u05E2\u05D4 \u05E9\u05D9\u05D7\u05D4 \u05D5\u05DC\u05D0 \u05E0\u05E7\u05D1\u05E2\u05D4 \u05E4\u05D2\u05D9\u05E9\u05D4.</p></div><strong>${rows.length}</strong></div><p class="workspace-note callback-disclaimer">\u05E9\u05D9\u05E0\u05D5\u05D9 \u05D4\u05E9\u05DC\u05D1 \u05DE\u05EA\u05E2\u05D3 \u05D4\u05D7\u05DC\u05D8\u05D4 \u05E9\u05DC \u05D4\u05E6\u05D5\u05D5\u05EA. \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA \u05DC\u05D0 \u05DE\u05EA\u05E7\u05E9\u05E8\u05EA \u05D5\u05DC\u05D0 \u05E7\u05D5\u05D1\u05E2\u05EA \u05E4\u05D2\u05D9\u05E9\u05D4.</p><div class="workspace-list">${list}</div></section>`;
}
function chip(value, label2) {
  const safe = knownStatuses.has(value) ? value : "unknown";
  return `<span class="status-chip status-${safe}">${escapeHtml(label2)}</span>`;
}
function brand() {
  return `<a class="brand brand-inverse" href="/" aria-label="devSkyline, \u05D3\u05E3 \u05D4\u05D1\u05D9\u05EA"><img src="/logo.png" alt="devSkyline" width="2172" height="724"></a>`;
}
function adminBootHtml() {
  return `<main id="main-content" class="admin-boot"><p role="status">\u05D8\u05D5\u05E2\u05E0\u05D9\u05DD \u05D0\u05EA \u05DE\u05E8\u05D7\u05D1 \u05D4\u05E2\u05D1\u05D5\u05D3\u05D4\u2026</p></main>`;
}
function adminLoginHtml({ googleEnabled: googleEnabled2 = false, identityError: identityError2 = false, adminError: adminError2 = "" } = {}) {
  return `<div class="login-shell"><div class="login-brand"><div class="login-brand-top">${brand()}<span>PRIVATE WORKSPACE</span></div><div class="login-brand-main"><p>STUDIO OPERATIONS / 01</p><h1>\u05DB\u05DC \u05DE\u05D4 \u05E9\u05E6\u05E8\u05D9\u05DA.<br><em>\u05D1\u05DE\u05E7\u05D5\u05DD \u05D0\u05D7\u05D3.</em></h1><span>\u05E0\u05D9\u05D4\u05D5\u05DC \u05E2\u05D1\u05D5\u05D3\u05D4, \u05DC\u05E7\u05D5\u05D7\u05D5\u05EA \u05D5\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8\u05D9\u05DD.</span></div><div class="login-brand-bottom"><span>devSkyline \xA9 2026</span><a href="/">\u05D7\u05D6\u05E8\u05D4 \u05DC\u05D0\u05EA\u05E8 \u2197</a></div></div><main class="login-main" id="main-content"><div class="login-card"><span class="login-indicator"><i></i> \u05D2\u05D9\u05E9\u05D4 \u05DC\u05D7\u05D1\u05E8\u05D9 \u05E6\u05D5\u05D5\u05EA \u05D1\u05DC\u05D1\u05D3</span><h2>\u05DB\u05E0\u05D9\u05E1\u05D4 \u05DC\u05DE\u05E2\u05E8\u05DB\u05EA</h2><p>\u05D4\u05E9\u05EA\u05DE\u05E9\u05D5 \u05D1\u05D7\u05E9\u05D1\u05D5\u05DF \u05E9\u05D4\u05D5\u05D6\u05DE\u05DF \u05DC\u05DE\u05E8\u05D7\u05D1 \u05D4\u05E2\u05D1\u05D5\u05D3\u05D4.</p><form id="login-form"><label for="login-email">\u05DB\u05EA\u05D5\u05D1\u05EA \u05D0\u05D9\u05DE\u05D9\u05D9\u05DC</label><input id="login-email" type="email" autocomplete="username" required placeholder="name@example.com"><label for="login-password">\u05E1\u05D9\u05E1\u05DE\u05D4</label><input id="login-password" type="password" autocomplete="current-password" required placeholder="\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05E9\u05DC\u05DB\u05DD"><button class="button button-primary" type="submit">\u05DB\u05E0\u05D9\u05E1\u05D4 \u05DC\u05DE\u05E2\u05E8\u05DB\u05EA \u2197</button><p class="form-status" role="status" aria-live="polite"></p></form><button class="forgot-link" id="forgot-password" type="button">\u05E9\u05DB\u05D7\u05EA\u05DD \u05E1\u05D9\u05E1\u05DE\u05D4?</button>${googleEnabled2 ? '<div class="login-divider">\u05D0\u05D5</div><button class="google-button" id="google-login" type="button"><span aria-hidden="true">G</span> \u05D4\u05DE\u05E9\u05DA \u05E2\u05DD Google</button>' : ""}<p class="login-help">\u05D6\u05E7\u05D5\u05E7\u05D9\u05DD \u05DC\u05E2\u05D6\u05E8\u05D4 \u05D1\u05DB\u05E0\u05D9\u05E1\u05D4? \u05E4\u05E0\u05D5 \u05DC\u05DE\u05E0\u05D4\u05DC \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA.</p>${identityError2 ? '<p class="login-error" role="alert">\u05DC\u05D0 \u05E0\u05D9\u05EA\u05DF \u05DC\u05D4\u05EA\u05D7\u05D1\u05E8 \u05DB\u05E8\u05D2\u05E2. \u05D1\u05D3\u05E7\u05D5 \u05D0\u05EA \u05D4\u05D2\u05D3\u05E8\u05D5\u05EA Identity \u05D1\u05BENetlify \u05D5\u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.</p>' : ""}${adminError2 ? `<p class="login-error" role="alert">${escapeHtml(adminError2)}</p>` : ""}</div></main></div>`;
}
function passwordPageHtml(type) {
  const invite = type === "invite";
  return `<div class="login-shell"><div class="login-brand"><div class="login-brand-top">${brand()}</div><div class="login-brand-main"><p>STUDIO OPERATIONS / 01</p><h1>${invite ? "\u05D1\u05E8\u05D5\u05DB\u05D9\u05DD \u05D4\u05D1\u05D0\u05D9\u05DD." : "\u05D7\u05D5\u05D6\u05E8\u05D9\u05DD \u05DC\u05E2\u05D1\u05D5\u05D3."}</h1></div><div class="login-brand-bottom"><a href="/">\u05D7\u05D6\u05E8\u05D4 \u05DC\u05D0\u05EA\u05E8 \u2197</a></div></div><main class="login-main" id="main-content"><div class="login-card"><span class="login-indicator"><i></i>${invite ? "\u05D4\u05E9\u05DC\u05DE\u05EA \u05D4\u05D6\u05DE\u05E0\u05D4" : "\u05E9\u05D7\u05D6\u05D5\u05E8 \u05D2\u05D9\u05E9\u05D4"}</span><h2>${invite ? "\u05D1\u05D7\u05E8\u05D5 \u05E1\u05D9\u05E1\u05DE\u05D4" : "\u05D4\u05D2\u05D3\u05D9\u05E8\u05D5 \u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D3\u05E9\u05D4"}</h2><p>\u05D1\u05D7\u05E8\u05D5 \u05E1\u05D9\u05E1\u05DE\u05D4 \u05D9\u05D9\u05D7\u05D5\u05D3\u05D9\u05EA \u05D1\u05EA \u05E9\u05DE\u05D5\u05E0\u05D4 \u05EA\u05D5\u05D5\u05D9\u05DD \u05DC\u05E4\u05D7\u05D5\u05EA.</p><form id="password-form"><label for="new-password">\u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D3\u05E9\u05D4</label><input id="new-password" type="password" autocomplete="new-password" minlength="8" required><label for="confirm-password">\u05D0\u05D9\u05DE\u05D5\u05EA \u05E1\u05D9\u05E1\u05DE\u05D4</label><input id="confirm-password" type="password" autocomplete="new-password" minlength="8" required><button class="button button-primary" type="submit">${invite ? "\u05E7\u05D1\u05DC\u05EA \u05D4\u05D4\u05D6\u05DE\u05E0\u05D4" : "\u05E9\u05DE\u05D9\u05E8\u05EA \u05D4\u05E1\u05D9\u05E1\u05DE\u05D4"} \u2197</button><p class="form-status" role="status" aria-live="polite"></p></form></div></main></div>`;
}
function mfaPageHtml({ enrolled = false, mfaSetup: mfaSetup2 = null } = {}) {
  const codeField = enrolled ? '<label for="mfa-code">\u05E7\u05D5\u05D3 \u05DE\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D4 \u05D0\u05D5 \u05E7\u05D5\u05D3 \u05D2\u05D9\u05D1\u05D5\u05D9</label><input id="mfa-code" type="text" autocomplete="one-time-code" pattern="([0-9]{6}|[A-Fa-f0-9]{16}|[A-Fa-f0-9]{4}(-[A-Fa-f0-9]{4}){3})" maxlength="19" required placeholder="000000 \u05D0\u05D5 \u05E7\u05D5\u05D3 \u05D2\u05D9\u05D1\u05D5\u05D9">' : '<label for="mfa-code">\u05E7\u05D5\u05D3 \u05D1\u05DF 6 \u05E1\u05E4\u05E8\u05D5\u05EA</label><input id="mfa-code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required placeholder="000000">';
  return `<div class="login-shell"><div class="login-brand"><div class="login-brand-top">${brand()}<span>PRIVATE WORKSPACE</span></div><div class="login-brand-main"><p>SECURITY / 02</p><h1>\u05E2\u05D5\u05D3 \u05E6\u05E2\u05D3 \u05D0\u05D7\u05D3.<br><em>\u05D5\u05E0\u05DB\u05E0\u05E1\u05D9\u05DD.</em></h1><span>\u05D4\u05D2\u05D9\u05E9\u05D4 \u05DC\u05E0\u05EA\u05D5\u05E0\u05D9 \u05D4\u05E2\u05E1\u05E7 \u05DE\u05D5\u05D2\u05E0\u05EA \u05D1\u05E7\u05D5\u05D3 \u05D7\u05D3\u05BE\u05E4\u05E2\u05DE\u05D9.</span></div><div class="login-brand-bottom"><span>devSkyline \xA9 2026</span><a href="/">\u05D7\u05D6\u05E8\u05D4 \u05DC\u05D0\u05EA\u05E8 \u2197</a></div></div><main class="login-main" id="main-content"><div class="login-card mfa-card"><span class="login-indicator"><i></i> \u05D0\u05D9\u05DE\u05D5\u05EA \u05DE\u05D5\u05D2\u05DF</span><h2>${enrolled ? "\u05D0\u05D9\u05DE\u05D5\u05EA \u05D3\u05D5\u05BE\u05E9\u05DC\u05D1\u05D9" : "\u05D4\u05E4\u05E2\u05DC\u05EA \u05D0\u05D9\u05DE\u05D5\u05EA \u05D3\u05D5\u05BE\u05E9\u05DC\u05D1\u05D9"}</h2><p>${enrolled ? "\u05D4\u05D6\u05D9\u05E0\u05D5 \u05E7\u05D5\u05D3 \u05DE\u05D4\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D4 \u05D0\u05D5 \u05E7\u05D5\u05D3 \u05D2\u05D9\u05D1\u05D5\u05D9 \u05E9\u05DC\u05D0 \u05D4\u05E9\u05EA\u05DE\u05E9\u05EA\u05DD \u05D1\u05D5." : "\u05E4\u05EA\u05D7\u05D5 \u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D9\u05EA \u05D0\u05D9\u05DE\u05D5\u05EA \u05D5\u05D4\u05D5\u05E1\u05D9\u05E4\u05D5 \u05D0\u05DC\u05D9\u05D4 \u05D0\u05EA \u05D7\u05E9\u05D1\u05D5\u05DF devSkyline."}</p>${!enrolled && !mfaSetup2 ? '<button class="button button-primary" id="mfa-start" type="button">\u05D9\u05E6\u05D9\u05E8\u05EA \u05DE\u05E4\u05EA\u05D7 \u05DC\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D4 \u2197</button>' : ""}${!enrolled && mfaSetup2 ? `<div class="mfa-secret"><span>\u05DE\u05E4\u05EA\u05D7 \u05DC\u05D4\u05D2\u05D3\u05E8\u05D4 \u05D9\u05D3\u05E0\u05D9\u05EA</span><code dir="ltr">${escapeHtml(mfaSetup2.secret)}</code><a href="${escapeHtml(mfaSetup2.uri)}">\u05E4\u05EA\u05D9\u05D7\u05D4 \u05D1\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D9\u05EA \u05D0\u05D9\u05DE\u05D5\u05EA \u2197</a><small>\u05E9\u05DE\u05E8\u05D5 \u05D0\u05EA \u05D4\u05DE\u05E4\u05EA\u05D7 \u05D1\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D9\u05EA \u05D4\u05D0\u05D9\u05DE\u05D5\u05EA. \u05DC\u05D0\u05D7\u05E8 \u05DE\u05DB\u05DF \u05D4\u05D6\u05D9\u05E0\u05D5 \u05D0\u05EA \u05D4\u05E7\u05D5\u05D3 \u05E9\u05DE\u05D5\u05E4\u05D9\u05E2 \u05D1\u05D4.</small></div>` : ""}${enrolled || mfaSetup2 ? `<form id="mfa-form">${codeField}<button class="button button-primary" type="submit">\u05D0\u05D9\u05DE\u05D5\u05EA \u05D5\u05DB\u05E0\u05D9\u05E1\u05D4 \u2197</button><p class="form-status" role="status" aria-live="polite"></p></form>` : '<p class="form-status" role="status" aria-live="polite"></p>'}<button class="forgot-link" id="logout-button" type="button">\u05D9\u05E6\u05D9\u05D0\u05D4 \u05DE\u05D4\u05D7\u05E9\u05D1\u05D5\u05DF</button></div></main></div>`;
}
function recoveryPageHtml(codes = []) {
  return `<div class="login-shell"><div class="login-brand"><div class="login-brand-top">${brand()}<span>PRIVATE WORKSPACE</span></div><div class="login-brand-main"><p>SECURITY / 03</p><h1>\u05E9\u05D5\u05DE\u05E8\u05D9\u05DD \u05D2\u05D9\u05E9\u05D4.<br><em>\u05D2\u05DD \u05DC\u05D4\u05DE\u05E9\u05DA.</em></h1><span>\u05E7\u05D5\u05D3\u05D9 \u05D2\u05D9\u05D1\u05D5\u05D9 \u05DC\u05DE\u05E7\u05E8\u05D4 \u05E9\u05DC\u05D0 \u05EA\u05D4\u05D9\u05D4 \u05D2\u05D9\u05E9\u05D4 \u05DC\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D9\u05EA \u05D4\u05D0\u05D9\u05DE\u05D5\u05EA.</span></div><div class="login-brand-bottom"><span>devSkyline \xA9 2026</span><a href="/">\u05D7\u05D6\u05E8\u05D4 \u05DC\u05D0\u05EA\u05E8 \u2197</a></div></div><main class="login-main" id="main-content"><div class="login-card mfa-card recovery-card"><span class="login-indicator"><i></i> \u05E7\u05D5\u05D3\u05D9\u05DD \u05DC\u05E9\u05D9\u05DE\u05D5\u05E9 \u05D7\u05D3\u05BE\u05E4\u05E2\u05DE\u05D9</span><h2>\u05E9\u05DE\u05E8\u05D5 \u05D0\u05EA \u05E7\u05D5\u05D3\u05D9 \u05D4\u05D2\u05D9\u05D1\u05D5\u05D9</h2><p>\u05DB\u05DC \u05E7\u05D5\u05D3 \u05E2\u05D5\u05D1\u05D3 \u05E4\u05E2\u05DD \u05D0\u05D7\u05EA \u05D1\u05DC\u05D1\u05D3. \u05E9\u05DE\u05E8\u05D5 \u05D0\u05D5\u05EA\u05DD \u05D1\u05DE\u05E7\u05D5\u05DD \u05E4\u05E8\u05D8\u05D9 \u05D5\u05D1\u05D8\u05D5\u05D7. \u05DC\u05D0\u05D7\u05E8 \u05E1\u05D2\u05D9\u05E8\u05EA \u05D4\u05DE\u05E1\u05DA \u05DC\u05D0 \u05E0\u05E6\u05D9\u05D2 \u05D0\u05D5\u05EA\u05DD \u05E9\u05D5\u05D1.</p><div class="recovery-list" dir="ltr">${(codes || []).map((code) => `<code>${escapeHtml(code)}</code>`).join("")}</div><button class="button button-primary" id="recovery-continue" type="button">\u05E9\u05DE\u05E8\u05EA\u05D9 \u05D0\u05EA \u05D4\u05E7\u05D5\u05D3\u05D9\u05DD, \u05DB\u05E0\u05D9\u05E1\u05D4 \u2197</button></div></main></div>`;
}
function workspaceHtml(adminData2) {
  const { clients = [], projects = [], ledger = [], monthly = [], leads = [], contributions = [], documents = [], team = [], user, settings = {}, permissions = {} } = adminData2 || {};
  const canManage = Boolean(permissions.manage);
  const owner = user?.role === "owner";
  const clientOptions = clients.map((client) => [client.id, client.name]);
  const projectOptions = projects.map((project) => [project.id, project.name]);
  const ledgerOptions = ledger.map((entry) => [entry.id, `${entry.description} \xB7 ${String(entry.occurred_on).slice(0, 10)}`]);
  const memberOptions = [[user?.id, user?.name || "\u05D0\u05E0\u05D9"], ...team.filter((member) => member.active).map((member) => [member.identity_user_id, member.name])].filter(([memberId]) => memberId);
  return `
    ${permissions.leads ? callbackSection(leads, canManage) : ""}
    ${permissions.leads ? `<section class="workspace-section" id="leads"><div class="workspace-heading"><div><span>01 / INQUIRIES</span><h2>\u05E4\u05E0\u05D9\u05D5\u05EA</h2><p>\u05E9\u05D9\u05D7\u05D5\u05EA \u05D7\u05D3\u05E9\u05D5\u05EA \u05E9\u05E0\u05DB\u05E0\u05E1\u05D5 \u05DE\u05D4\u05D0\u05EA\u05E8 \u05D5\u05D4\u05E9\u05DC\u05D1 \u05D4\u05D1\u05D0 \u05E9\u05DC\u05D4\u05DF.</p></div><strong>${leads.length}</strong></div><div class="workspace-list">${leads.length ? leads.map((lead) => `<article class="workspace-row"><div><b>${escapeHtml(lead.name)}</b>${chip(lead.status, leadStageLabel(lead))}<span>${escapeHtml(lead.contact)}</span><p>${escapeHtml(lead.message || lead.service || "\u05E4\u05E0\u05D9\u05D9\u05D4 \u05DB\u05DC\u05DC\u05D9\u05EA")}</p></div>${canManage ? `<label>\u05E9\u05DC\u05D1<select class="lead-status" data-id="${escapeHtml(lead.id)}">${options(leadStages, lead.status)}</select></label>` : chip(lead.status, stageName(leadStages, lead.status))}</article>`).join("") : '<p class="workspace-empty">\u05D0\u05D9\u05DF \u05E4\u05E0\u05D9\u05D5\u05EA \u05E2\u05D3\u05D9\u05D9\u05DF. \u05E4\u05E0\u05D9\u05D5\u05EA \u05DE\u05D4\u05D8\u05D5\u05E4\u05E1 \u05D9\u05D5\u05E4\u05D9\u05E2\u05D5 \u05DB\u05D0\u05DF.</p>'}</div></section>` : ""}
    ${permissions.leads ? `<section class="workspace-section" id="clients"><div class="workspace-heading"><div><span>02 / CLIENTS</span><h2>\u05DC\u05E7\u05D5\u05D7\u05D5\u05EA</h2><p>\u05DB\u05E8\u05D8\u05D9\u05E1\u05D9 \u05DC\u05E7\u05D5\u05D7, \u05E4\u05E8\u05D8\u05D9 \u05E7\u05E9\u05E8 \u05D5\u05D4\u05E2\u05E8\u05D5\u05EA \u05E2\u05D1\u05D5\u05D3\u05D4.</p></div><strong>${clients.length}</strong></div>${canManage ? `<form id="client-form" class="workspace-form"><h3 id="client-form-title">\u05DC\u05E7\u05D5\u05D7 \u05D7\u05D3\u05E9</h3><div class="workspace-form-grid"><label>\u05E9\u05DD \u05D4\u05DC\u05E7\u05D5\u05D7 \u05D0\u05D5 \u05D4\u05E2\u05E1\u05E7<input name="name" maxlength="120" required></label><label>\u05E9\u05DD \u05D4\u05D7\u05D1\u05E8\u05D4<input name="company" maxlength="120"></label><label>\u05D3\u05E8\u05DA \u05E7\u05E9\u05E8<input name="contact" maxlength="160"></label><label class="wide">\u05D4\u05E2\u05E8\u05D5\u05EA<textarea name="notes" maxlength="2000" rows="2"></textarea></label></div><div class="workspace-form-actions"><button class="button button-primary" type="submit">\u05E9\u05DE\u05D9\u05E8\u05EA \u05DC\u05E7\u05D5\u05D7 \u2197</button><button class="button button-outline" id="client-cancel" type="button" hidden>\u05D1\u05D9\u05D8\u05D5\u05DC \u05E2\u05E8\u05D9\u05DB\u05D4</button><p class="form-status" role="status" aria-live="polite"></p></div></form>` : ""}<div class="workspace-list">${clients.length ? clients.map((client) => `<article class="workspace-row"><div><b>${escapeHtml(client.name)}</b><span>${escapeHtml(client.company || "\u05DC\u05DC\u05D0 \u05D7\u05D1\u05E8\u05D4")}</span><p>${escapeHtml(client.contact || client.notes || "\u05DC\u05D0 \u05E0\u05D5\u05E1\u05E4\u05D5 \u05E4\u05E8\u05D8\u05D9\u05DD")}</p></div>${canManage ? `<button class="row-action edit-client" data-id="${escapeHtml(client.id)}" type="button">\u05E2\u05E8\u05D9\u05DB\u05D4 \u2197</button>` : ""}</article>`).join("") : '<p class="workspace-empty">\u05E2\u05D5\u05D3 \u05DC\u05D0 \u05E0\u05D5\u05E1\u05E4\u05D5 \u05DC\u05E7\u05D5\u05D7\u05D5\u05EA. \u05D4\u05EA\u05D7\u05D9\u05DC\u05D5 \u05DE\u05DB\u05E8\u05D8\u05D9\u05E1 \u05D4\u05DC\u05E7\u05D5\u05D7 \u05D4\u05E8\u05D0\u05E9\u05D5\u05DF.</p>'}</div></section>` : ""}
    <section class="workspace-section" id="projects"><div class="workspace-heading"><div><span>03 / PROJECTS</span><h2>\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8\u05D9\u05DD</h2><p>\u05DE\u05E2\u05E7\u05D1 \u05D0\u05D7\u05E8 \u05DC\u05E7\u05D5\u05D7, \u05E9\u05DC\u05D1, \u05EA\u05E7\u05E6\u05D9\u05D1 \u05D5\u05D7\u05DC\u05D5\u05E7\u05EA \u05D4\u05E2\u05D1\u05D5\u05D3\u05D4.</p></div><strong>${projects.length}</strong></div>${canManage ? `<form id="project-form" class="workspace-form"><h3 id="project-form-title">\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05D7\u05D3\u05E9</h3><div class="workspace-form-grid"><label>\u05E9\u05DD \u05D4\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8<input name="name" maxlength="120" required></label><label>\u05DC\u05E7\u05D5\u05D7<select name="client_id"><option value="">\u05DC\u05DC\u05D0 \u05DC\u05E7\u05D5\u05D7 \u05DE\u05E9\u05D5\u05D9\u05DA</option>${options(clientOptions)}</select></label><label>\u05E9\u05DC\u05D1<select name="status">${options(projectStages)}</select></label><label>\u05EA\u05E7\u05E6\u05D9\u05D1 \u05DE\u05EA\u05D5\u05DB\u05E0\u05DF \u20AA<input name="budget_ils" type="number" min="0" max="999999999" step="0.01" value="0" required></label><label class="wide">\u05E4\u05E8\u05D8\u05D9 \u05E2\u05D1\u05D5\u05D3\u05D4 \u05D5\u05D4\u05E9\u05DC\u05D1 \u05D4\u05D1\u05D0<textarea name="notes" maxlength="3000" rows="2"></textarea></label></div><div class="workspace-form-actions"><button class="button button-primary" type="submit">\u05E9\u05DE\u05D9\u05E8\u05EA \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u2197</button><button class="button button-outline" id="project-cancel" type="button" hidden>\u05D1\u05D9\u05D8\u05D5\u05DC \u05E2\u05E8\u05D9\u05DB\u05D4</button><p class="form-status" role="status" aria-live="polite"></p></div></form>` : ""}<div class="workspace-list">${projects.length ? projects.map((project) => `<article class="workspace-row"><div><b>${escapeHtml(project.name)}</b>${chip(project.status, stageName(projectStages, project.status))}<span>${escapeHtml(project.client_name || "\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05E4\u05E0\u05D9\u05DE\u05D9")}</span><p>${escapeHtml(project.notes || "\u05DC\u05D0 \u05E0\u05D5\u05E1\u05E4\u05D5 \u05E4\u05E8\u05D8\u05D9 \u05E2\u05D1\u05D5\u05D3\u05D4")}</p>${permissions.finance ? `<small>\u05EA\u05E7\u05E6\u05D9\u05D1: ${moneyLabel(project.budget_ils)}</small>` : ""}${contributions.filter((item) => Number(item.project_id) === Number(project.id)).length ? `<small>\u05D7\u05DC\u05D5\u05E7\u05EA \u05E2\u05D1\u05D5\u05D3\u05D4: ${contributions.filter((item) => Number(item.project_id) === Number(project.id)).map((item) => `${escapeHtml(item.contributor_name)} ${Number(item.share_percent)}%`).join(" \xB7 ")}</small>` : ""}</div>${canManage ? `<button class="row-action edit-project" data-id="${escapeHtml(project.id)}" type="button">\u05E2\u05E8\u05D9\u05DB\u05D4 \u2197</button>` : ""}</article>`).join("") : '<p class="workspace-empty">\u05E2\u05D3\u05D9\u05D9\u05DF \u05D0\u05D9\u05DF \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8\u05D9\u05DD. \u05D0\u05E4\u05E9\u05E8 \u05DC\u05D4\u05D5\u05E1\u05D9\u05E3 \u05D2\u05DD \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05E4\u05E0\u05D9\u05DE\u05D9.</p>'}</div>${owner && projects.length ? `<form id="contribution-form" class="workspace-form workspace-subform"><h3>\u05D7\u05DC\u05D5\u05E7\u05EA \u05E2\u05D1\u05D5\u05D3\u05D4 \u05D1\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8</h3><div class="workspace-form-grid"><label>\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8<select name="project_id" required>${options(projectOptions)}</select></label><label>\u05D7\u05D1\u05E8 \u05E6\u05D5\u05D5\u05EA<select name="identity_user_id" required>${options(memberOptions)}</select></label><label>\u05D7\u05DC\u05E7 \u05D1\u05E2\u05D1\u05D5\u05D3\u05D4 %<input name="share_percent" type="number" min="0" max="100" step="0.01" required></label><label class="wide">\u05DE\u05D4 \u05D1\u05D5\u05E6\u05E2<textarea name="work_note" maxlength="1000" rows="2"></textarea></label></div><div class="workspace-form-actions"><button class="button button-primary" type="submit">\u05E9\u05DE\u05D9\u05E8\u05EA \u05D7\u05DC\u05D5\u05E7\u05D4 \u2197</button><p class="form-status" role="status" aria-live="polite"></p></div><p class="workspace-note">\u05E1\u05DA \u05D4\u05D0\u05D7\u05D5\u05D6\u05D9\u05DD \u05D1\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05DE\u05D5\u05D2\u05D1\u05DC \u05DC\u05BE100%. \u05D0\u05E4\u05E9\u05E8 \u05DC\u05E2\u05D3\u05DB\u05DF \u05D7\u05DC\u05D5\u05E7\u05D4 \u05E7\u05D9\u05D9\u05DE\u05EA.</p></form>` : ""}</section>
    ${contributions.length ? `<section class="workspace-section" id="allocation"><div class="workspace-heading"><div><span>WORK / ALLOCATION</span><h2>\u05DE\u05D9 \u05E2\u05E9\u05D4 \u05DE\u05D4</h2><p>\u05D7\u05DC\u05D5\u05E7\u05EA \u05D4\u05E2\u05D1\u05D5\u05D3\u05D4 \u05D5\u05D4\u05EA\u05D9\u05E2\u05D5\u05D3 \u05E9\u05D1\u05D5\u05E6\u05E2 \u05D1\u05DB\u05DC \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8.</p></div></div><div class="workspace-list">${contributions.map((item) => `<article class="workspace-row"><div><b>${escapeHtml(item.contributor_name)} \xB7 ${escapeHtml(projects.find((project) => Number(project.id) === Number(item.project_id))?.name || "\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8")}</b><span>${Number(item.share_percent)}% \u05DE\u05D4\u05E2\u05D1\u05D5\u05D3\u05D4</span><p>${escapeHtml(item.work_note || "\u05DC\u05D0 \u05E0\u05D5\u05E1\u05E3 \u05E4\u05D9\u05E8\u05D5\u05D8 \u05E2\u05D1\u05D5\u05D3\u05D4")}</p></div></article>`).join("")}</div></section>` : ""}
    ${permissions.finance ? `<section class="workspace-section" id="finance"><div class="workspace-heading"><div><span>04 / FINANCE</span><h2>\u05DB\u05E1\u05E4\u05D9\u05DD \u05D5\u05E7\u05D5\u05E4\u05D4</h2><p>\u05D9\u05EA\u05E8\u05D4 \u05DE\u05D7\u05D5\u05E9\u05D1\u05EA \u05DE\u05D9\u05EA\u05E8\u05EA \u05E4\u05EA\u05D9\u05D7\u05D4, \u05D4\u05DB\u05E0\u05E1\u05D5\u05EA \u05D5\u05D4\u05D5\u05E6\u05D0\u05D5\u05EA \u05E9\u05D4\u05D5\u05D6\u05E0\u05D5 \u05DC\u05DE\u05E2\u05E8\u05DB\u05EA.</p></div><strong>${moneyLabel(adminData2.totals?.balance_ils)}</strong></div>${owner ? `<form id="opening-form" class="workspace-form workspace-subform"><h3>\u05D9\u05EA\u05E8\u05EA \u05E4\u05EA\u05D9\u05D7\u05D4 \u05D1\u05E7\u05D5\u05E4\u05D4</h3><div class="workspace-form-grid"><label>\u05E1\u05DB\u05D5\u05DD \u05D4\u05EA\u05D7\u05DC\u05EA\u05D9 \u20AA<input name="opening_balance_ils" type="number" min="0" max="999999999" step="0.01" required value="${Number(settings?.opening_balance_ils || 0)}"></label></div><div class="workspace-form-actions"><button class="button button-outline" type="submit">\u05E2\u05D3\u05DB\u05D5\u05DF \u05D9\u05EA\u05E8\u05EA \u05E4\u05EA\u05D9\u05D7\u05D4</button><p class="form-status" role="status" aria-live="polite"></p></div><p class="workspace-note">\u05D4\u05D2\u05D3\u05D9\u05E8\u05D5 \u05E4\u05E2\u05DD \u05D0\u05D7\u05EA \u05D0\u05EA \u05D4\u05E1\u05DB\u05D5\u05DD \u05E9\u05D4\u05D9\u05D4 \u05D1\u05E7\u05D5\u05E4\u05D4 \u05DC\u05E4\u05E0\u05D9 \u05EA\u05D7\u05D9\u05DC\u05EA \u05D4\u05E8\u05D9\u05E9\u05D5\u05DD \u05DB\u05D0\u05DF. \u05D4\u05DB\u05E0\u05E1\u05D5\u05EA \u05D5\u05D4\u05D5\u05E6\u05D0\u05D5\u05EA \u05D9\u05EA\u05D5\u05D5\u05E1\u05E4\u05D5 \u05D0\u05DC\u05D9\u05D5.</p></form>` : ""}<form id="entry-form" class="workspace-form"><h3>\u05E8\u05D9\u05E9\u05D5\u05DD \u05EA\u05E0\u05D5\u05E2\u05D4 \u05D7\u05D3\u05E9\u05D4</h3><div class="workspace-form-grid"><label>\u05E1\u05D5\u05D2 \u05EA\u05E0\u05D5\u05E2\u05D4<select name="entry_type"><option value="income">\u05D4\u05DB\u05E0\u05E1\u05D4</option><option value="expense">\u05D4\u05D5\u05E6\u05D0\u05D4</option></select></label><label>\u05E1\u05D9\u05D5\u05D5\u05D2<select name="category"><option value="business">\u05E4\u05E2\u05D9\u05DC\u05D5\u05EA \u05D4\u05E2\u05E1\u05E7</option><option value="internal">\u05E4\u05E0\u05D9\u05DE\u05D9</option><option value="project">\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05DC\u05E7\u05D5\u05D7</option></select></label><label>\u05E1\u05DB\u05D5\u05DD \u20AA<input name="amount_ils" type="number" min="0.01" max="999999999" step="0.01" required></label><label>\u05EA\u05D0\u05E8\u05D9\u05DA<input name="occurred_on" type="date" required value="${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}"></label><label>\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05E7\u05E9\u05D5\u05E8<select name="project_id"><option value="">\u05DC\u05DC\u05D0 \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8</option>${options(projectOptions)}</select></label><label>\u05D0\u05E1\u05DE\u05DB\u05EA\u05D0 \u05D0\u05D5 \u05DE\u05E1\u05E4\u05E8 \u05D7\u05E9\u05D1\u05D5\u05E0\u05D9\u05EA<input name="reference" maxlength="160"></label><label class="wide">\u05EA\u05D9\u05D0\u05D5\u05E8 \u05D4\u05EA\u05E0\u05D5\u05E2\u05D4<input name="description" maxlength="300" required placeholder="\u05DC\u05D3\u05D5\u05D2\u05DE\u05D4: \u05EA\u05E9\u05DC\u05D5\u05DD \u05E8\u05D0\u05E9\u05D5\u05DF \u05E2\u05D1\u05D5\u05E8 \u05D0\u05EA\u05E8"></label></div><div class="workspace-form-actions"><button class="button button-primary" type="submit">\u05E9\u05DE\u05D9\u05E8\u05EA \u05EA\u05E0\u05D5\u05E2\u05D4 \u2197</button><p class="form-status" role="status" aria-live="polite"></p></div><p class="workspace-note">\u05E8\u05D9\u05E9\u05D5\u05DE\u05D9 \u05DB\u05E1\u05E4\u05D9\u05DD \u05E0\u05E9\u05DE\u05E8\u05D9\u05DD \u05D1\u05D9\u05D5\u05DE\u05DF \u05E4\u05E2\u05D5\u05DC\u05D5\u05EA \u05D5\u05D0\u05D9\u05E0\u05DD \u05E0\u05DE\u05D7\u05E7\u05D9\u05DD \u05DE\u05EA\u05D5\u05DA \u05D4\u05DE\u05E1\u05DA. \u05D0\u05D9\u05DF \u05DC\u05E8\u05D0\u05D5\u05EA \u05D1\u05E1\u05D9\u05DB\u05D5\u05DD \u05D4\u05D6\u05D4 \u05EA\u05D7\u05DC\u05D9\u05E3 \u05DC\u05D4\u05E0\u05D4\u05DC\u05EA \u05D7\u05E9\u05D1\u05D5\u05E0\u05D5\u05EA.</p></form><div class="workspace-columns"><div><h3>\u05EA\u05E0\u05D5\u05E2\u05D5\u05EA \u05D0\u05D7\u05E8\u05D5\u05E0\u05D5\u05EA</h3><div class="workspace-list">${ledger.length ? ledger.map((entry) => `<article class="workspace-row compact"><div><b>${escapeHtml(entry.description)}</b><span>${escapeHtml(entry.project_name || (entry.category === "internal" ? "\u05E4\u05E0\u05D9\u05DE\u05D9" : "\u05E4\u05E2\u05D9\u05DC\u05D5\u05EA \u05D4\u05E2\u05E1\u05E7"))} \xB7 ${escapeHtml(entry.reference || "")}</span><small>${escapeHtml(String(entry.occurred_on).slice(0, 10))}</small></div><strong class="${entry.entry_type === "income" ? "positive" : "negative"}">${entry.entry_type === "income" ? "+" : "\u2212"}${moneyLabel(entry.amount_ils)}</strong></article>`).join("") : '<p class="workspace-empty">\u05DC\u05D0 \u05E0\u05E8\u05E9\u05DE\u05D5 \u05EA\u05E0\u05D5\u05E2\u05D5\u05EA \u05E2\u05D3\u05D9\u05D9\u05DF.</p>'}</div></div><div><h3>\u05E1\u05D9\u05DB\u05D5\u05DD \u05D7\u05D5\u05D3\u05E9\u05D9</h3><div class="workspace-list">${monthly.length ? monthly.map((month) => `<article class="month-row"><b>${escapeHtml(month.month)}</b><span>\u05D4\u05DB\u05E0\u05E1\u05D5\u05EA ${moneyLabel(month.income_ils)}</span><span>\u05D4\u05D5\u05E6\u05D0\u05D5\u05EA ${moneyLabel(month.expense_ils)}</span><strong>${moneyLabel(Number(month.income_ils) - Number(month.expense_ils))}</strong></article>`).join("") : '<p class="workspace-empty">\u05E0\u05EA\u05D5\u05E0\u05D9 \u05D7\u05D5\u05D3\u05E9\u05D9\u05DD \u05D9\u05D5\u05E4\u05D9\u05E2\u05D5 \u05DC\u05D0\u05D7\u05E8 \u05E8\u05D9\u05E9\u05D5\u05DD \u05EA\u05E0\u05D5\u05E2\u05D4.</p>'}</div></div></div></section>` : ""}
    ${permissions.finance ? `<section class="workspace-section" id="documents"><div class="workspace-heading"><div><span>05 / DOCUMENTS</span><h2>\u05D7\u05E9\u05D1\u05D5\u05E0\u05D9\u05D5\u05EA \u05D5\u05E7\u05D1\u05DC\u05D5\u05EA</h2><p>\u05E7\u05D1\u05E6\u05D9\u05DD \u05E4\u05E8\u05D8\u05D9\u05D9\u05DD \u05D4\u05DE\u05E9\u05D5\u05D9\u05DB\u05D9\u05DD \u05DC\u05EA\u05E0\u05D5\u05E2\u05D4 \u05DB\u05E1\u05E4\u05D9\u05EA \u05D5\u05E4\u05EA\u05D5\u05D7\u05D9\u05DD \u05E8\u05E7 \u05DC\u05D1\u05E2\u05DC\u05D9 \u05D4\u05E8\u05E9\u05D0\u05EA \u05DB\u05E1\u05E4\u05D9\u05DD.</p></div><strong>${documents.length}</strong></div>${ledger.length ? `<form id="document-form" class="workspace-form" enctype="multipart/form-data"><h3>\u05D4\u05E2\u05DC\u05D0\u05EA \u05DE\u05E1\u05DE\u05DA</h3><div class="workspace-form-grid"><label>\u05EA\u05E0\u05D5\u05E2\u05D4 \u05DB\u05E1\u05E4\u05D9\u05EA<select name="ledger_entry_id" required>${options(ledgerOptions)}</select></label><label>\u05E1\u05D5\u05D2 \u05DE\u05E1\u05DE\u05DA<select name="kind"><option value="invoice">\u05D7\u05E9\u05D1\u05D5\u05E0\u05D9\u05EA</option><option value="receipt">\u05E7\u05D1\u05DC\u05D4</option><option value="other">\u05DE\u05E1\u05DE\u05DA \u05D0\u05D7\u05E8</option></select></label><label class="wide">\u05E7\u05D5\u05D1\u05E5 PDF \u05D0\u05D5 \u05EA\u05DE\u05D5\u05E0\u05D4<input name="file" type="file" accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg" required></label></div><div class="workspace-form-actions"><button class="button button-primary" type="submit">\u05E9\u05DE\u05D9\u05E8\u05EA \u05DE\u05E1\u05DE\u05DA \u2197</button><p class="form-status" role="status" aria-live="polite"></p></div><p class="workspace-note">\u05D2\u05D5\u05D3\u05DC \u05DE\u05E8\u05D1\u05D9: 4 MB. \u05D4\u05DE\u05E1\u05DE\u05DA \u05D9\u05D9\u05E9\u05DE\u05E8 \u05D1\u05D0\u05D5\u05E4\u05DF \u05E4\u05E8\u05D8\u05D9 \u05D5\u05D9\u05D4\u05D9\u05D4 \u05D6\u05DE\u05D9\u05DF \u05DC\u05D4\u05D5\u05E8\u05D3\u05D4 \u05E8\u05E7 \u05DC\u05D0\u05D7\u05E8 \u05DB\u05E0\u05D9\u05E1\u05D4 \u05D5\u05D0\u05D9\u05DE\u05D5\u05EA \u05D3\u05D5\u05BE\u05E9\u05DC\u05D1\u05D9.</p></form>` : '<p class="workspace-empty workspace-pad">\u05D4\u05D5\u05E1\u05D9\u05E4\u05D5 \u05EA\u05E0\u05D5\u05E2\u05D4 \u05DB\u05E1\u05E4\u05D9\u05EA \u05DC\u05E4\u05E0\u05D9 \u05D4\u05E2\u05DC\u05D0\u05EA \u05DE\u05E1\u05DE\u05DA.</p>'}<div class="workspace-list">${documents.length ? documents.map((document2) => `<article class="workspace-row"><div><b>${escapeHtml(document2.filename)}</b><span>${escapeHtml(document2.entry_description)} \xB7 ${escapeHtml(document2.kind === "invoice" ? "\u05D7\u05E9\u05D1\u05D5\u05E0\u05D9\u05EA" : document2.kind === "receipt" ? "\u05E7\u05D1\u05DC\u05D4" : "\u05DE\u05E1\u05DE\u05DA \u05D0\u05D7\u05E8")}</span><small>${new Intl.NumberFormat("he-IL").format(Math.ceil(Number(document2.size_bytes) / 1024))} KB</small></div><a class="row-action" href="/api/admin-document?id=${encodeURIComponent(document2.id)}">\u05D4\u05D5\u05E8\u05D3\u05EA \u05DE\u05E1\u05DE\u05DA \u2197</a></article>`).join("") : '<p class="workspace-empty">\u05E2\u05D3\u05D9\u05D9\u05DF \u05DC\u05D0 \u05E0\u05E9\u05DE\u05E8\u05D5 \u05DE\u05E1\u05DE\u05DB\u05D9\u05DD.</p>'}</div></section>` : ""}
  `;
}
function adminDashboardHtml(adminData2) {
  const leads = adminData2?.leads || [];
  const projects = adminData2?.projects || [];
  const ledger = adminData2?.ledger || [];
  const totals = adminData2?.totals || {};
  const team = adminData2?.team || [];
  const invitations = adminData2?.invitations || [];
  const user = adminData2?.user;
  const owner = user?.role === "owner";
  const finance = Boolean(adminData2?.permissions?.finance);
  const canSeeLeads = Boolean(adminData2?.permissions?.leads);
  const income = Number(totals.income_ils || 0);
  const expense = Number(totals.expense_ils || 0);
  const navLink = (href, label2) => `<a href="${href}">${label2}</a>`;
  return `<div class="dashboard-shell">
    <aside class="dashboard-nav" id="admin-nav">${brand()}<span>WORKSPACE</span><p class="admin-role">${escapeHtml(roleName(user?.role))}</p><nav aria-label="\u05E0\u05D9\u05D5\u05D5\u05D8 \u05DE\u05E0\u05D4\u05DC">${navLink("#overview", "\u05E1\u05E7\u05D9\u05E8\u05D4")}${canSeeLeads ? `${navLink("#callbacks", "\u05E9\u05D9\u05D7\u05D5\u05EA \u05D7\u05D5\u05D6\u05E8\u05D5\u05EA")}${navLink("#leads", "\u05E4\u05E0\u05D9\u05D5\u05EA")}${navLink("#clients", "\u05DC\u05E7\u05D5\u05D7\u05D5\u05EA")}` : ""}${navLink("#projects", "\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8\u05D9\u05DD")}${finance ? `${navLink("#finance", "\u05DB\u05E1\u05E4\u05D9\u05DD \u05D5\u05E7\u05D5\u05E4\u05D4")}${navLink("#documents", "\u05DE\u05E1\u05DE\u05DB\u05D9\u05DD")}` : ""}${owner ? navLink("#team", "\u05E0\u05D9\u05D4\u05D5\u05DC \u05E6\u05D5\u05D5\u05EA") : ""}${navLink("#security", "\u05D0\u05D1\u05D8\u05D7\u05D4")}</nav><button id="logout-button" type="button">\u05D9\u05E6\u05D9\u05D0\u05D4 \u05DE\u05D4\u05DE\u05E2\u05E8\u05DB\u05EA \u2197</button></aside>
    <main id="main-content" class="dashboard-main">
      <div class="dashboard-top" id="overview"><button class="admin-menu" id="admin-menu" type="button" aria-controls="admin-nav" aria-expanded="false" aria-label="\u05E4\u05EA\u05D9\u05D7\u05EA \u05EA\u05E4\u05E8\u05D9\u05D8 \u05D4\u05E0\u05D9\u05D4\u05D5\u05DC"><span></span><span></span><span></span></button><div><p>DEVSKYLINE / OPERATIONS</p><h1>\u05DE\u05E8\u05D7\u05D1 \u05D4\u05E2\u05D1\u05D5\u05D3\u05D4</h1></div><a href="/" class="line-link">\u05DC\u05D0\u05EA\u05E8 \u05D4\u05E6\u05D9\u05D1\u05D5\u05E8\u05D9 \u2197</a></div>
      <p class="dashboard-intro">${user?.name ? `<span>\u05E9\u05DC\u05D5\u05DD</span> <b>${escapeHtml(user.name)}</b>. ` : ""}${finance ? "\u05E0\u05EA\u05D5\u05E0\u05D9\u05DD \u05DE\u05E2\u05D5\u05D3\u05DB\u05E0\u05D9\u05DD \u05DE\u05D4\u05DE\u05E2\u05E8\u05DB\u05EA. \u05D4\u05E0\u05EA\u05D5\u05E0\u05D9\u05DD \u05D4\u05DB\u05E1\u05E4\u05D9\u05D9\u05DD \u05DE\u05E9\u05E7\u05E4\u05D9\u05DD \u05E8\u05E9\u05D5\u05DE\u05D5\u05EA \u05E9\u05E0\u05E7\u05DC\u05D8\u05D5 \u05D1\u05DE\u05E2\u05E8\u05DB\u05EA \u05D1\u05DC\u05D1\u05D3." : "\u05E0\u05EA\u05D5\u05E0\u05D9\u05DD \u05DE\u05E2\u05D5\u05D3\u05DB\u05E0\u05D9\u05DD \u05DE\u05D4\u05DE\u05E2\u05E8\u05DB\u05EA \u05D1\u05D4\u05EA\u05D0\u05DD \u05DC\u05D4\u05E8\u05E9\u05D0\u05D4 \u05E9\u05DC\u05DB\u05DD."}</p>
      <div class="dashboard-metrics">
        ${canSeeLeads ? `<article><span>\u05DB\u05DC \u05D4\u05E4\u05E0\u05D9\u05D5\u05EA</span><strong>${escapeHtml(totals.lead_count || 0)}</strong></article>` : ""}
        ${canSeeLeads ? `<article><span>\u05DC\u05E7\u05D5\u05D7\u05D5\u05EA</span><strong>${escapeHtml(totals.client_count || 0)}</strong></article>` : ""}<article><span>\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8\u05D9\u05DD</span><strong>${escapeHtml(totals.project_count || 0)}</strong></article>
        ${finance ? `<article><span>\u05D9\u05EA\u05E8\u05D4 \u05D1\u05E7\u05D5\u05E4\u05D4</span><strong>${shekel(Number(totals.balance_ils || 0))}</strong></article><article><span>\u05D4\u05DB\u05E0\u05E1\u05D5\u05EA \u05E8\u05E9\u05D5\u05DE\u05D5\u05EA</span><strong>${shekel(income)}</strong></article><article><span>\u05D4\u05D5\u05E6\u05D0\u05D5\u05EA \u05E8\u05E9\u05D5\u05DE\u05D5\u05EA</span><strong>${shekel(expense)}</strong></article>` : ""}
      </div>
      ${canSeeLeads ? `<section class="dashboard-table"><div><h2>\u05E4\u05E0\u05D9\u05D5\u05EA \u05D0\u05D7\u05E8\u05D5\u05E0\u05D5\u05EA</h2><a href="#leads">\u05DB\u05DC \u05D4\u05E4\u05E0\u05D9\u05D5\u05EA \u2197</a></div>${leads.length ? `<ul>${leads.slice(0, 3).map((lead) => `<li><strong>${escapeHtml(lead.name)}</strong><span>${escapeHtml(lead.service || "\u05E4\u05E0\u05D9\u05D9\u05D4 \u05DB\u05DC\u05DC\u05D9\u05EA")}</span>${chip(lead.status, leadStageLabel(lead))}</li>`).join("")}</ul>` : '<p class="workspace-empty">\u05E2\u05D3\u05D9\u05D9\u05DF \u05D0\u05D9\u05DF \u05E4\u05E0\u05D9\u05D5\u05EA \u05DC\u05D4\u05E6\u05D2\u05D4.</p>'}</section>` : ""}
      <section class="dashboard-table"><div><h2>\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8\u05D9\u05DD \u05D0\u05D7\u05E8\u05D5\u05E0\u05D9\u05DD</h2><a href="#projects">\u05DB\u05DC \u05D4\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8\u05D9\u05DD \u2197</a></div>${projects.length ? `<ul>${projects.slice(0, 3).map((project) => `<li><strong>${escapeHtml(project.name)}</strong>${chip(project.status, stageName(projectStages, project.status))}</li>`).join("")}</ul>` : '<p class="workspace-empty">\u05E2\u05D3\u05D9\u05D9\u05DF \u05D0\u05D9\u05DF \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8\u05D9\u05DD \u05DC\u05D4\u05E6\u05D2\u05D4.</p>'}</section>
      ${finance ? `<section class="dashboard-table"><div><h2>\u05EA\u05E0\u05D5\u05E2\u05D5\u05EA \u05DB\u05E1\u05E4\u05D9\u05D5\u05EA \u05D0\u05D7\u05E8\u05D5\u05E0\u05D5\u05EA</h2><a href="#finance">\u05DB\u05DC \u05D4\u05EA\u05E0\u05D5\u05E2\u05D5\u05EA \u2197</a></div>${ledger.length ? `<ul>${ledger.slice(0, 3).map((entry) => `<li><strong>${escapeHtml(entry.description)}</strong><span>${escapeHtml(entry.entry_type === "income" ? "\u05D4\u05DB\u05E0\u05E1\u05D4" : entry.entry_type === "expense" ? "\u05D4\u05D5\u05E6\u05D0\u05D4" : "\u05EA\u05E0\u05D5\u05E2\u05D4")}</span><span>${shekel(Number(entry.amount_ils || 0))}</span></li>`).join("")}</ul>` : '<p class="workspace-empty">\u05E2\u05D3\u05D9\u05D9\u05DF \u05D0\u05D9\u05DF \u05EA\u05E0\u05D5\u05E2\u05D5\u05EA \u05DC\u05D4\u05E6\u05D2\u05D4.</p>'}</section>` : ""}
      ${workspaceHtml(adminData2)}
      <section class="workspace-section" id="security"><div class="workspace-heading"><div><span>SECURITY / ACCESS</span><h2>\u05D0\u05D1\u05D8\u05D7\u05EA \u05D4\u05D7\u05E9\u05D1\u05D5\u05DF</h2><p>\u05E6\u05E8\u05D5 \u05E7\u05D5\u05D3\u05D9 \u05D2\u05D9\u05D1\u05D5\u05D9 \u05D7\u05D3\u05E9\u05D9\u05DD \u05D0\u05DD \u05D4\u05E7\u05D5\u05D3\u05D9\u05DD \u05D4\u05E7\u05D5\u05D3\u05DE\u05D9\u05DD \u05D0\u05D1\u05D3\u05D5. \u05D9\u05E6\u05D9\u05E8\u05EA \u05E7\u05D5\u05D3\u05D9\u05DD \u05D7\u05D3\u05E9\u05D9\u05DD \u05DE\u05D1\u05D8\u05DC\u05EA \u05D0\u05EA \u05D4\u05D9\u05E9\u05E0\u05D9\u05DD.</p></div></div><form id="recovery-form" class="workspace-form"><div class="workspace-form-grid"><label>\u05E7\u05D5\u05D3 \u05D7\u05D3\u05E9 \u05DE\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D9\u05EA \u05D4\u05D0\u05D9\u05DE\u05D5\u05EA<input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required placeholder="000000"></label></div><div class="workspace-form-actions"><button class="button button-outline" type="submit">\u05D9\u05E6\u05D9\u05E8\u05EA \u05E7\u05D5\u05D3\u05D9 \u05D2\u05D9\u05D1\u05D5\u05D9 \u2197</button><p class="form-status" role="status" aria-live="polite"></p></div><p class="workspace-note">\u05D7\u05DB\u05D5 \u05E9\u05D4\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D4 \u05EA\u05E6\u05D9\u05D2 \u05E7\u05D5\u05D3 \u05D7\u05D3\u05E9 \u05DC\u05D0\u05D7\u05E8 \u05D4\u05DB\u05E0\u05D9\u05E1\u05D4. \u05E7\u05D5\u05D3\u05D9 \u05D4\u05D2\u05D9\u05D1\u05D5\u05D9 \u05D9\u05D5\u05E6\u05D2\u05D5 \u05E4\u05E2\u05DD \u05D0\u05D7\u05EA \u05D1\u05DC\u05D1\u05D3.</p></form></section>
      ${owner ? `<section class="dashboard-team" id="team"><div class="dashboard-team-heading"><p>ACCESS / TEAM</p><h2>\u05D7\u05D1\u05E8\u05D9 \u05E6\u05D5\u05D5\u05EA \u05D5\u05D4\u05D6\u05DE\u05E0\u05D5\u05EA</h2><span>\u05E8\u05E7 \u05D1\u05E2\u05DC \u05D4\u05D7\u05E9\u05D1\u05D5\u05DF \u05D9\u05DB\u05D5\u05DC \u05DC\u05D4\u05D6\u05DE\u05D9\u05DF \u05DE\u05E9\u05EA\u05DE\u05E9\u05D9\u05DD \u05D7\u05D3\u05E9\u05D9\u05DD.</span></div><form id="invite-form" class="invite-form"><label>\u05E9\u05DD \u05DE\u05DC\u05D0<input name="name" autocomplete="off" maxlength="120" required placeholder="\u05E9\u05DD \u05D4\u05DE\u05D5\u05D6\u05DE\u05DF \u05D0\u05D5 \u05D4\u05DE\u05D5\u05D6\u05DE\u05E0\u05EA"></label><label>\u05DB\u05EA\u05D5\u05D1\u05EA \u05D0\u05D9\u05DE\u05D9\u05D9\u05DC<input name="email" type="email" autocomplete="off" maxlength="160" required placeholder="name@example.com"></label><label>\u05D4\u05E8\u05E9\u05D0\u05D4<select name="role"><option value="developer">\u05DE\u05E4\u05EA\u05D7/\u05EA</option><option value="admin">\u05DE\u05E0\u05D4\u05DC/\u05EA</option><option value="viewer">\u05E6\u05E4\u05D9\u05D9\u05D4 \u05D1\u05DC\u05D1\u05D3</option></select></label><button class="button button-primary" type="submit">\u05E9\u05DC\u05D9\u05D7\u05EA \u05E7\u05D9\u05E9\u05D5\u05E8 \u05D4\u05E6\u05D8\u05E8\u05E4\u05D5\u05EA \u2197</button><p class="form-status" role="status" aria-live="polite"></p></form><div class="team-list"><div><h3>\u05D7\u05D1\u05E8\u05D9 \u05E6\u05D5\u05D5\u05EA \u05E4\u05E2\u05D9\u05DC\u05D9\u05DD</h3>${team.length ? `<ul>${team.map((member) => `<li><strong>${escapeHtml(member.name)}</strong><span>${escapeHtml(member.email)}</span><em>${escapeHtml(roleName(member.role))}</em></li>`).join("")}</ul>` : '<p class="workspace-empty">\u05E2\u05D3\u05D9\u05D9\u05DF \u05D0\u05D9\u05DF \u05D7\u05D1\u05E8\u05D9 \u05E6\u05D5\u05D5\u05EA \u05E0\u05D5\u05E1\u05E4\u05D9\u05DD.</p>'}</div><div><h3>\u05D4\u05D6\u05DE\u05E0\u05D5\u05EA \u05D0\u05D7\u05E8\u05D5\u05E0\u05D5\u05EA</h3>${invitations.length ? `<ul>${invitations.map((invite) => `<li><strong>${escapeHtml(invite.name)}</strong><span>${escapeHtml(invite.email)}</span><em>${escapeHtml(invite.status)}</em></li>`).join("")}</ul>` : '<p class="workspace-empty">\u05E2\u05D3\u05D9\u05D9\u05DF \u05DC\u05D0 \u05E0\u05E9\u05DC\u05D7\u05D5 \u05D4\u05D6\u05DE\u05E0\u05D5\u05EA.</p>'}</div></div></section>` : ""}
    </main>
  </div>`;
}

// src/admin/accessibility.js
var KEY = "devskyline-access-v2";
var defaults = {
  fontSize: 100,
  wordSpacing: 0,
  letterSpacing: 0,
  lineHeight: 1.6,
  dyslexia: false,
  headings: false,
  links: false,
  theme: "default",
  contrast: false,
  saturated: false,
  grayscale: false,
  muted: false,
  invert: false,
  reading: false,
  guide: false,
  hideImages: false,
  cursorLarge: false,
  cursorWhite: false,
  motion: false,
  textColor: "",
  headingColor: "",
  backgroundColor: ""
};
var prefs = load();
var speaking = false;
function load() {
  try {
    return { ...defaults, ...JSON.parse(localStorage.getItem(KEY) || "{}") };
  } catch {
    return { ...defaults };
  }
}
function save() {
  localStorage.setItem(KEY, JSON.stringify(prefs));
  apply();
}
var label = (he, en, language2) => language2 === "en" ? en : he;
function toggle(key, he, en, language2) {
  return `<button type="button" class="a11y-option" data-a11y-toggle="${key}" aria-pressed="false"><span class="a11y-option-icon" aria-hidden="true">${key === "motion" ? "\u25EB" : key === "guide" ? "\u25AC" : key === "links" ? "\u2197" : "\u25C9"}</span><span>${label(he, en, language2)}</span><span class="a11y-switch" aria-hidden="true"></span></button>`;
}
function range(key, he, en, language2, min, max, step, suffix) {
  return `<label class="a11y-range"><span>${label(he, en, language2)} <output data-a11y-output="${key}"></output></span><input type="range" data-a11y-range="${key}" min="${min}" max="${max}" step="${step}" value="${defaults[key]}" aria-label="${label(he, en, language2)}"><small>${label("\u05E8\u05D2\u05D9\u05DC", "Default", language2)} <b>${suffix}</b></small></label>`;
}
function color(key, he, en, language2) {
  return `<div class="a11y-color"><label for="a11y-${key}">${label(he, en, language2)}</label><button type="button" data-a11y-clear-color="${key}">${label("\u05D1\u05DC\u05D9 \u05E6\u05D1\u05E2 \u05DE\u05D5\u05EA\u05D0\u05DD", "No custom color", language2)}</button><input id="a11y-${key}" type="color" data-a11y-color="${key}" value="#000c34" aria-label="${label(he, en, language2)}"></div>`;
}
function accessibilityMarkup(language2) {
  return `<button class="access-trigger" type="button" aria-label="${label("\u05E4\u05EA\u05D9\u05D7\u05EA \u05D4\u05EA\u05D0\u05DE\u05D5\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA", "Open accessibility settings", language2)}" aria-controls="access-panel" aria-expanded="false"><svg viewBox="0 0 40 40" aria-hidden="true"><circle cx="20" cy="7" r="3.5" fill="currentColor"/><path d="M7 14c8 3 18 3 26 0M20 17v8m0 0-7 10m7-10 7 10" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></svg></button>
  <aside id="access-panel" class="access-panel" aria-labelledby="access-heading" hidden>
    <div class="access-heading"><div><small>DEVSKYLINE / ACCESSIBILITY</small><h2 id="access-heading">${label("\u05D4\u05EA\u05D0\u05DE\u05D5\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA \u05D1\u05D0\u05EA\u05E8", "Accessibility settings", language2)}</h2></div><button type="button" class="access-close" aria-label="${label("\u05D4\u05E1\u05EA\u05E8\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA", "Close accessibility settings", language2)}">\xD7</button></div>
    <div class="a11y-toolbar"><button type="button" class="access-reset">${label("\u05D0\u05D9\u05E4\u05D5\u05E1 \u05D4\u05D2\u05D3\u05E8\u05D5\u05EA", "Reset settings", language2)}</button><a href="/accessibility">${label("\u05D4\u05E6\u05D4\u05E8\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA", "Accessibility statement", language2)}</a></div>
    <div class="a11y-scroll">
      <section><h3>${label("\u05D8\u05E7\u05E1\u05D8, \u05E7\u05E8\u05D9\u05D0\u05D4 \u05D5\u05E2\u05D9\u05E6\u05D5\u05D1 \u05EA\u05D5\u05DB\u05DF", "Text and reading", language2)}</h3>${range("fontSize", "\u05D2\u05D5\u05D3\u05DC \u05D8\u05E7\u05E1\u05D8", "Text size", language2, 100, 160, 10, "%")}${toggle("dyslexia", "\u05D2\u05D5\u05E4\u05DF \u05E7\u05E8\u05D9\u05D0 \u05DC\u05D3\u05D9\u05E1\u05DC\u05E7\u05E6\u05D9\u05D4", "Dyslexia-friendly font", language2)}${range("wordSpacing", "\u05E8\u05D5\u05D5\u05D7 \u05DE\u05D9\u05DC\u05D9\u05DD", "Word spacing", language2, 0, 0.4, 0.1, "em")}${toggle("headings", "\u05D4\u05D3\u05D2\u05E9\u05EA \u05DB\u05D5\u05EA\u05E8\u05D5\u05EA", "Highlight headings", language2)}${range("letterSpacing", "\u05E8\u05D5\u05D5\u05D7 \u05D0\u05D5\u05EA\u05D9\u05D5\u05EA", "Letter spacing", language2, 0, 0.16, 0.04, "em")}${toggle("links", "\u05D4\u05D3\u05D2\u05E9\u05EA \u05E7\u05D9\u05E9\u05D5\u05E8\u05D9\u05DD", "Highlight links", language2)}${range("lineHeight", "\u05D2\u05D5\u05D1\u05D4 \u05E9\u05D5\u05E8\u05D4", "Line height", language2, 1.6, 2.4, 0.2, "\xD7")}</section>
      <section><h3>${label("\u05DE\u05E8\u05D0\u05D4, \u05E6\u05D1\u05E2\u05D9\u05DD \u05D5\u05E0\u05D9\u05D2\u05D5\u05D3\u05D9\u05D5\u05EA", "Appearance and color", language2)}</h3><div class="a11y-theme"><button type="button" data-a11y-theme="dark">${label("\u05DE\u05E6\u05D1 \u05DB\u05D4\u05D4", "Dark", language2)}</button><button type="button" data-a11y-theme="light">${label("\u05DE\u05E6\u05D1 \u05D1\u05D4\u05D9\u05E8", "Light", language2)}</button><button type="button" data-a11y-theme="default">${label("\u05DE\u05E7\u05D5\u05E8\u05D9", "Original", language2)}</button></div>${toggle("contrast", "\u05E0\u05D9\u05D2\u05D5\u05D3\u05D9\u05D5\u05EA \u05D7\u05D6\u05E7\u05D4", "Strong contrast", language2)}${toggle("saturated", "\u05D4\u05D2\u05D1\u05E8\u05EA \u05E6\u05D1\u05E2\u05D9\u05DD", "Boost colors", language2)}${toggle("grayscale", "\u05EA\u05E6\u05D5\u05D2\u05D4 \u05D1\u05E9\u05D7\u05D5\u05E8 \u05DC\u05D1\u05DF", "Grayscale", language2)}${toggle("muted", "\u05D4\u05E4\u05D7\u05EA\u05EA \u05E6\u05D1\u05E2\u05D9\u05DD", "Reduce colors", language2)}${color("textColor", "\u05E6\u05D1\u05E2 \u05DC\u05D8\u05E7\u05E1\u05D8 \u05D1\u05D0\u05EA\u05E8", "Text color", language2)}${color("headingColor", "\u05E6\u05D1\u05E2 \u05DC\u05DB\u05D5\u05EA\u05E8\u05D5\u05EA", "Heading color", language2)}${color("backgroundColor", "\u05E6\u05D1\u05E2 \u05DC\u05E8\u05E7\u05E2 \u05D4\u05E2\u05DE\u05D5\u05D3", "Page background", language2)}<button type="button" class="a11y-reset-colors">${label("\u05D0\u05D9\u05E4\u05D5\u05E1 \u05E6\u05D1\u05E2\u05D9\u05DD \u05DE\u05D5\u05EA\u05D0\u05DE\u05D9\u05DD", "Reset custom colors", language2)}</button></section>
      <section><h3>${label("\u05D2\u05DC\u05D9\u05E9\u05D4, \u05E1\u05DE\u05DF \u05D5\u05EA\u05E0\u05D5\u05E2\u05D4", "Navigation and motion", language2)}</h3>${toggle("invert", "\u05E6\u05D1\u05E2\u05D9\u05DD \u05D4\u05E4\u05D5\u05DB\u05D9\u05DD", "Invert colors", language2)}${toggle("reading", "\u05DE\u05E6\u05D1 \u05E7\u05E8\u05D9\u05D0\u05D4", "Reading mode", language2)}${toggle("guide", "\u05DE\u05D3\u05E8\u05D9\u05DA \u05E7\u05E8\u05D9\u05D0\u05D4", "Reading guide", language2)}<button type="button" class="a11y-option" id="a11y-speak"><span class="a11y-option-icon" aria-hidden="true">\u25B6</span><span>${label("\u05D4\u05E7\u05E8\u05D0\u05D4 / \u05E2\u05E6\u05D9\u05E8\u05D4", "Read aloud / stop", language2)}</span></button>${toggle("hideImages", "\u05D4\u05E1\u05EA\u05E8\u05EA \u05EA\u05DE\u05D5\u05E0\u05D5\u05EA", "Hide images", language2)}${toggle("cursorLarge", "\u05E1\u05DE\u05DF \u05D2\u05D3\u05D5\u05DC", "Large cursor", language2)}${toggle("cursorWhite", "\u05E1\u05DE\u05DF \u05DC\u05D1\u05DF", "White cursor", language2)}${toggle("motion", "\u05E2\u05E6\u05D9\u05E8\u05EA \u05D0\u05E0\u05D9\u05DE\u05E6\u05D9\u05D5\u05EA", "Stop animations", language2)}</section>
      <section><h3>${label("\u05DE\u05D9\u05D3\u05E2 \u05D5\u05E2\u05D6\u05E8\u05D4", "Help and information", language2)}</h3><a class="a11y-help-link" href="/accessibility">${label("\u05D4\u05E6\u05D4\u05E8\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA \u05D5\u05DE\u05D9\u05D3\u05E2 \u05E0\u05D5\u05E1\u05E3", "Accessibility statement and more", language2)} \u2197</a><a class="a11y-help-link" href="/contact?topic=accessibility">${label("\u05D3\u05D9\u05D5\u05D5\u05D7 \u05E2\u05DC \u05D1\u05E2\u05D9\u05D9\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA", "Report an accessibility issue", language2)} \u2197</a><a class="a11y-help-link" href="mailto:ripping_births9f@icloud.com?subject=Accessibility%20inquiry">${label("\u05E4\u05E0\u05D9\u05D5\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA \u05D5\u05E4\u05E8\u05D8\u05D9 \u05D9\u05E6\u05D9\u05E8\u05EA \u05E7\u05E9\u05E8", "Accessibility contact", language2)} \u2197</a><a class="a11y-help-link" href="mailto:ripping_births9f@icloud.com?subject=Accessibility%20violation">${label("\u05D3\u05D9\u05D5\u05D5\u05D7 \u05E2\u05DC \u05D4\u05E4\u05E8\u05EA \u05E0\u05D2\u05D9\u05E9\u05D5\u05EA", "Report an accessibility violation", language2)} \u2197</a><details class="a11y-keyboard"><summary>${label("\u05DE\u05D3\u05E8\u05D9\u05DA \u05E0\u05D9\u05D5\u05D5\u05D8 \u05DE\u05E7\u05DC\u05D3\u05EA", "Keyboard navigation guide", language2)}</summary><p>${label("Tab \u05DC\u05DE\u05E2\u05D1\u05E8 \u05D1\u05D9\u05DF \u05E8\u05DB\u05D9\u05D1\u05D9\u05DD, Enter \u05D0\u05D5 \u05E8\u05D5\u05D5\u05D7 \u05DC\u05D4\u05E4\u05E2\u05DC\u05D4, Esc \u05DC\u05E1\u05D2\u05D9\u05E8\u05EA \u05D4\u05D7\u05DC\u05D5\u05E0\u05D9\u05EA. \u05E7\u05D9\u05E9\u05D5\u05E8 \u05D3\u05D9\u05DC\u05D5\u05D2 \u05DC\u05EA\u05D5\u05DB\u05DF \u05DE\u05D5\u05E4\u05D9\u05E2 \u05D1\u05EA\u05D7\u05D9\u05DC\u05EA \u05D4\u05E2\u05DE\u05D5\u05D3.", "Use Tab to move, Enter or Space to activate, and Esc to close this panel. A skip link appears at the start of the page.", language2)}</p></details></section>
    </div>
    <div class="a11y-bottom"><span>${label("\u05E9\u05E4\u05EA \u05DE\u05DE\u05E9\u05E7 \u05D4\u05E0\u05D2\u05D9\u05E9\u05D5\u05EA", "Panel language", language2)}</span><button type="button" class="a11y-lang" data-a11y-language="he" aria-pressed="${language2 === "he"}">\u05E2\u05D1\u05E8\u05D9\u05EA</button><button type="button" class="a11y-lang" data-a11y-language="en" aria-pressed="${language2 === "en"}">English</button></div>
  </aside><div class="a11y-guide" aria-hidden="true"></div>`;
}
function apply() {
  const html = document.documentElement;
  const classes = ["dyslexia", "headings", "links", "contrast", "saturated", "grayscale", "muted", "invert", "reading", "guide", "hideImages", "cursorLarge", "cursorWhite", "motion"];
  for (const key of classes) html.classList.toggle(`access-${key}`, Boolean(prefs[key]));
  for (const theme of ["dark", "light"]) html.classList.toggle(`access-theme-${theme}`, prefs.theme === theme);
  html.classList.toggle("access-text-scale", Number(prefs.fontSize) > 100);
  html.style.setProperty("--access-font-scale", String(Number(prefs.fontSize) / 100));
  html.style.setProperty("--access-word-spacing", `${Number(prefs.wordSpacing)}em`);
  html.style.setProperty("--access-letter-spacing", `${Number(prefs.letterSpacing)}em`);
  html.style.setProperty("--access-line-height", String(Number(prefs.lineHeight)));
  for (const key of ["textColor", "headingColor", "backgroundColor"]) html.style.setProperty(`--access-${key}`, prefs[key] || "initial");
  for (const key of ["textColor", "headingColor", "backgroundColor"]) html.classList.toggle(`access-custom-${key}`, Boolean(prefs[key]));
  document.querySelectorAll("[data-a11y-toggle]").forEach((button) => button.setAttribute("aria-pressed", String(Boolean(prefs[button.dataset.a11yToggle]))));
  document.querySelectorAll("[data-a11y-theme]").forEach((button) => button.setAttribute("aria-pressed", String(prefs.theme === button.dataset.a11yTheme)));
  document.querySelectorAll("[data-a11y-range]").forEach((input) => {
    input.value = prefs[input.dataset.a11yRange];
    const output = document.querySelector(`[data-a11y-output="${input.dataset.a11yRange}"]`);
    if (output) output.textContent = String(prefs[input.dataset.a11yRange]) + (input.dataset.a11yRange === "fontSize" ? "%" : "");
  });
  document.querySelectorAll("[data-a11y-color]").forEach((input) => {
    input.value = prefs[input.dataset.a11yColor] || "#000c34";
  });
}
function closeAccessibility() {
  const panel = document.querySelector("#access-panel");
  if (!panel || panel.hidden) return;
  panel.hidden = true;
  document.querySelector(".access-trigger")?.setAttribute("aria-expanded", "false");
  document.querySelector(".access-trigger")?.focus();
}
function bindAccessibility(onLanguage) {
  const trigger = document.querySelector(".access-trigger");
  trigger?.addEventListener("click", () => {
    const panel = document.querySelector("#access-panel");
    panel.hidden = !panel.hidden;
    trigger.setAttribute("aria-expanded", String(!panel.hidden));
    if (!panel.hidden) panel.querySelector(".access-close")?.focus();
  });
  document.querySelector(".access-close")?.addEventListener("click", closeAccessibility);
  document.querySelector(".access-reset")?.addEventListener("click", () => {
    prefs = { ...defaults };
    save();
  });
  document.querySelector(".a11y-reset-colors")?.addEventListener("click", () => {
    prefs.textColor = "";
    prefs.headingColor = "";
    prefs.backgroundColor = "";
    save();
  });
  document.querySelectorAll("[data-a11y-clear-color]").forEach((button) => button.addEventListener("click", () => {
    prefs[button.dataset.a11yClearColor] = "";
    save();
  }));
  document.querySelectorAll("[data-a11y-toggle]").forEach((button) => button.addEventListener("click", () => {
    const key = button.dataset.a11yToggle;
    prefs[key] = !prefs[key];
    if (key === "cursorWhite" && prefs[key]) prefs.cursorLarge = false;
    if (key === "cursorLarge" && prefs[key]) prefs.cursorWhite = false;
    if (key === "grayscale" && prefs[key]) prefs.muted = false;
    save();
  }));
  document.querySelectorAll("[data-a11y-range]").forEach((input) => input.addEventListener("input", () => {
    prefs[input.dataset.a11yRange] = Number(input.value);
    save();
  }));
  document.querySelectorAll("[data-a11y-theme]").forEach((button) => button.addEventListener("click", () => {
    prefs.theme = button.dataset.a11yTheme;
    save();
  }));
  document.querySelectorAll("[data-a11y-color]").forEach((input) => input.addEventListener("input", () => {
    prefs[input.dataset.a11yColor] = input.value;
    save();
  }));
  document.querySelectorAll("[data-a11y-language]").forEach((button) => button.addEventListener("click", () => onLanguage(button.dataset.a11yLanguage)));
  document.querySelector("#a11y-speak")?.addEventListener("click", () => {
    if (!("speechSynthesis" in window)) return;
    if (speaking) {
      speechSynthesis.cancel();
      speaking = false;
      return;
    }
    const selected = window.getSelection()?.toString().trim();
    const utterance = new SpeechSynthesisUtterance(selected || document.querySelector("#main-content")?.innerText.slice(0, 4e3) || "");
    utterance.lang = document.documentElement.lang === "en" ? "en-US" : "he-IL";
    utterance.onend = () => {
      speaking = false;
    };
    speechSynthesis.speak(utterance);
    speaking = true;
  });
  document.addEventListener("mousemove", (event) => {
    const guide = document.querySelector(".a11y-guide");
    if (guide && prefs.guide) guide.style.top = `${event.clientY - 16}px`;
  });
  apply();
}

// src/admin/main.js
var app = document.querySelector("#app");
var toast = document.querySelector("#toast");
var identity = null;
var identityCallback = null;
var identityError = false;
var googleEnabled = false;
var adminData = null;
var adminLoading = false;
var adminError = "";
var adminAuth = null;
var adminReady = false;
var mfaSetup = null;
var mfaRecoveryCodes = null;
var editingClientId = null;
var editingProjectId = null;
var language = localStorage.getItem("devskyline-language") === "en" ? "en" : "he";
var identityReady = Promise.resolve(main_exports).then(async (api) => {
  identity = api;
  identityCallback = await api.handleAuthCallback();
  const settings = await api.getSettings();
  googleEnabled = Boolean(settings.providers?.google);
  api.onAuthChange((event) => {
    if (event === "logout") {
      adminData = null;
      adminAuth = null;
      mfaSetup = null;
      mfaRecoveryCodes = null;
    }
    refreshAdmin();
  });
  adminReady = true;
  await refreshAdmin();
  return api;
}).catch(() => {
  identityError = true;
  adminReady = true;
  render();
  return null;
});
function accessibility() {
  return accessibilityMarkup(language);
}
function adminLogin() {
  return adminLoginHtml({ googleEnabled, identityError, adminError }) + accessibility();
}
function passwordPage(type) {
  return passwordPageHtml(type) + accessibility();
}
function mfaPage() {
  return mfaPageHtml({ enrolled: Boolean(adminAuth?.enrolled), mfaSetup }) + accessibility();
}
function recoveryPage() {
  return recoveryPageHtml(mfaRecoveryCodes) + accessibility();
}
function adminDashboard() {
  return adminDashboardHtml(adminData) + accessibility();
}
async function refreshAdmin() {
  if (!identity || adminLoading) return;
  adminLoading = true;
  try {
    const user = await identity.getUser();
    if (user) {
      const status = await fetch("/api/admin-auth", { credentials: "same-origin", cache: "no-store" });
      if (!status.ok) {
        adminAuth = null;
        adminData = null;
        adminError = status.status === 403 ? "\u05DC\u05D7\u05E9\u05D1\u05D5\u05DF \u05D4\u05D6\u05D4 \u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4 \u05DC\u05DE\u05E8\u05D7\u05D1 \u05D4\u05E2\u05D1\u05D5\u05D3\u05D4." : "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D1\u05D3\u05D5\u05E7 \u05D0\u05EA \u05D4\u05E8\u05E9\u05D0\u05D5\u05EA \u05D4\u05D7\u05E9\u05D1\u05D5\u05DF.";
      } else {
        adminAuth = await status.json();
        adminError = "";
        if (adminAuth.verified) {
          const response = await fetch("/api/admin-data", { credentials: "same-origin", cache: "no-store" });
          if (response.ok) adminData = await response.json();
          else {
            adminData = null;
            if (response.status === 428) adminAuth.verified = false;
            else adminError = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D8\u05E2\u05D5\u05DF \u05D0\u05EA \u05E0\u05EA\u05D5\u05E0\u05D9 \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA.";
          }
        } else adminData = null;
      }
    } else {
      adminData = null;
      adminAuth = null;
      mfaSetup = null;
      mfaRecoveryCodes = null;
    }
  } catch {
    adminData = null;
    adminError = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D1\u05D3\u05D5\u05E7 \u05D0\u05EA \u05D4\u05E8\u05E9\u05D0\u05D5\u05EA \u05D4\u05D7\u05E9\u05D1\u05D5\u05DF.";
  } finally {
    adminLoading = false;
    render();
  }
}
function render() {
  document.documentElement.classList.add("is-admin");
  const pending = !adminReady && !identityCallback && !mfaRecoveryCodes && !adminData && !adminAuth;
  app.innerHTML = pending ? adminBootHtml() + accessibility() : identityCallback?.type === "invite" || identityCallback?.type === "recovery" ? passwordPage(identityCallback.type) : mfaRecoveryCodes ? recoveryPage() : adminData ? adminDashboard() : adminAuth ? mfaPage() : adminLogin();
  if (!pending && adminError) showToast(adminError);
  document.title = "\u05D0\u05D6\u05D5\u05E8 \u05E6\u05D5\u05D5\u05EA | devSkyline";
  document.documentElement.lang = "he";
  document.documentElement.dir = "rtl";
  bind();
  bindAccessibility((newLanguage) => {
    language = newLanguage;
    localStorage.setItem("devskyline-language", language);
    render();
    document.querySelector(".access-trigger")?.click();
  });
}
function bind() {
  document.querySelector("#login-form")?.addEventListener("submit", submitLogin);
  document.querySelector("#forgot-password")?.addEventListener("click", async () => {
    const email = document.querySelector("#login-email");
    const status = document.querySelector("#login-form .form-status");
    if (!email.checkValidity()) {
      status.textContent = "\u05D4\u05D6\u05D9\u05E0\u05D5 \u05DB\u05EA\u05D5\u05D1\u05EA \u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05DB\u05D3\u05D9 \u05DC\u05E7\u05D1\u05DC \u05E7\u05D9\u05E9\u05D5\u05E8 \u05DC\u05D0\u05D9\u05E4\u05D5\u05E1.";
      email.focus();
      return;
    }
    await identityReady;
    if (!identity) return void (status.textContent = "\u05E9\u05D9\u05E8\u05D5\u05EA \u05D4\u05D4\u05EA\u05D7\u05D1\u05E8\u05D5\u05EA \u05D0\u05D9\u05E0\u05D5 \u05D6\u05DE\u05D9\u05DF \u05DB\u05E8\u05D2\u05E2.");
    try {
      await identity.requestPasswordRecovery(email.value.trim());
      status.textContent = "\u05D0\u05DD \u05E7\u05D9\u05D9\u05DD \u05D7\u05E9\u05D1\u05D5\u05DF \u05DC\u05DB\u05EA\u05D5\u05D1\u05EA \u05D4\u05D6\u05D5, \u05D9\u05D9\u05E9\u05DC\u05D7 \u05D0\u05DC\u05D9\u05D4 \u05E7\u05D9\u05E9\u05D5\u05E8 \u05DC\u05D0\u05D9\u05E4\u05D5\u05E1.";
    } catch {
      status.textContent = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05E9\u05DC\u05D5\u05D7 \u05E7\u05D9\u05E9\u05D5\u05E8 \u05DB\u05E8\u05D2\u05E2. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1 \u05D1\u05E2\u05D5\u05D3 \u05DB\u05DE\u05D4 \u05D3\u05E7\u05D5\u05EA.";
    }
  });
  document.querySelector("#google-login")?.addEventListener("click", async () => {
    await identityReady;
    if (!identity) return showToast("\u05E9\u05D9\u05E8\u05D5\u05EA \u05D4\u05D4\u05EA\u05D7\u05D1\u05E8\u05D5\u05EA \u05D0\u05D9\u05E0\u05D5 \u05D6\u05DE\u05D9\u05DF \u05DB\u05E8\u05D2\u05E2.");
    try {
      await identity.oauthLogin("google");
    } catch {
      showToast("\u05DB\u05E0\u05D9\u05E1\u05D4 \u05E2\u05DD Google \u05D0\u05D9\u05E0\u05D4 \u05D6\u05DE\u05D9\u05E0\u05D4 \u05DB\u05E8\u05D2\u05E2. \u05D1\u05D3\u05E7\u05D5 \u05E9\u05D4\u05D0\u05E4\u05E9\u05E8\u05D5\u05EA \u05D4\u05D5\u05E4\u05E2\u05DC\u05D4 \u05D1\u05BENetlify.");
    }
  });
  document.querySelector("#password-form")?.addEventListener("submit", submitPassword);
  document.querySelector("#mfa-start")?.addEventListener("click", startMfa);
  document.querySelector("#mfa-form")?.addEventListener("submit", submitMfa);
  document.querySelector("#recovery-continue")?.addEventListener("click", async () => {
    mfaRecoveryCodes = null;
    await refreshAdmin();
  });
  document.querySelector("#recovery-form")?.addEventListener("submit", regenerateRecovery);
  document.querySelector("#invite-form")?.addEventListener("submit", submitInvite);
  for (const [formId, action] of [["client-form", "createClient"], ["project-form", "createProject"], ["entry-form", "addEntry"], ["opening-form", "setOpeningBalance"], ["contribution-form", "setContribution"]]) {
    document.getElementById(formId)?.addEventListener("submit", (event) => submitRecord(event, action));
  }
  document.getElementById("document-form")?.addEventListener("submit", submitDocument);
  document.querySelectorAll(".lead-status").forEach((select) => select.addEventListener("change", async () => {
    select.disabled = true;
    const result = await saveRecord({ action: "updateLead", id: select.dataset.id, status: select.value });
    if (result.ok) await refreshAdmin();
    else {
      select.disabled = false;
      showToast("\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05E2\u05D3\u05DB\u05DF \u05D0\u05EA \u05D4\u05E4\u05E0\u05D9\u05D9\u05D4. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.");
    }
  }));
  document.querySelectorAll(".edit-client").forEach((button) => button.addEventListener("click", () => editClient(button.dataset.id)));
  document.querySelectorAll(".edit-project").forEach((button) => button.addEventListener("click", () => editProject(button.dataset.id)));
  document.querySelector("#client-cancel")?.addEventListener("click", () => resetEdit("client"));
  document.querySelector("#project-cancel")?.addEventListener("click", () => resetEdit("project"));
  const adminMenu = document.querySelector("#admin-menu");
  adminMenu?.addEventListener("click", () => {
    const open = adminMenu.getAttribute("aria-expanded") !== "true";
    adminMenu.setAttribute("aria-expanded", String(open));
    adminMenu.setAttribute("aria-label", open ? language === "he" ? "\u05E1\u05D2\u05D9\u05E8\u05EA \u05EA\u05E4\u05E8\u05D9\u05D8 \u05D4\u05E0\u05D9\u05D4\u05D5\u05DC" : "Close workspace menu" : language === "he" ? "\u05E4\u05EA\u05D9\u05D7\u05EA \u05EA\u05E4\u05E8\u05D9\u05D8 \u05D4\u05E0\u05D9\u05D4\u05D5\u05DC" : "Open workspace menu");
    document.querySelector("#admin-nav")?.classList.toggle("is-open", open);
  });
  document.querySelectorAll("#admin-nav a").forEach((link) => link.addEventListener("click", () => {
    adminMenu?.setAttribute("aria-expanded", "false");
    adminMenu?.setAttribute("aria-label", language === "he" ? "\u05E4\u05EA\u05D9\u05D7\u05EA \u05EA\u05E4\u05E8\u05D9\u05D8 \u05D4\u05E0\u05D9\u05D4\u05D5\u05DC" : "Open workspace menu");
    document.querySelector("#admin-nav")?.classList.remove("is-open");
  }));
  document.querySelector("#logout-button")?.addEventListener("click", async () => {
    await fetch("/api/admin-auth", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "logout" }) }).catch(() => {
    });
    await identity?.logout();
    adminData = null;
    adminAuth = null;
    mfaSetup = null;
    mfaRecoveryCodes = null;
    render();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const panel = document.querySelector("#access-panel");
    if (panel && !panel.hidden) {
      closeAccessibility();
      return;
    }
    const adminMenu2 = document.querySelector("#admin-menu");
    const adminNav = document.querySelector("#admin-nav");
    if (adminMenu2?.getAttribute("aria-expanded") === "true") {
      adminMenu2.setAttribute("aria-expanded", "false");
      adminMenu2.setAttribute("aria-label", language === "he" ? "\u05E4\u05EA\u05D9\u05D7\u05EA \u05EA\u05E4\u05E8\u05D9\u05D8 \u05D4\u05E0\u05D9\u05D4\u05D5\u05DC" : "Open workspace menu");
      adminNav?.classList.remove("is-open");
      adminMenu2.focus();
    }
  }, { once: true });
}
async function saveRecord(input) {
  try {
    const response = await fetch("/api/admin-records", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input)
    });
    return { ok: response.ok, body: await response.json() };
  } catch {
    return { ok: false, body: { error: "network" } };
  }
}
async function submitDocument(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector(".form-status");
  const button = form.querySelector('button[type="submit"]');
  const body = new FormData(form);
  const file = body.get("file");
  if (!file || !file.size) return void (status.textContent = "\u05D1\u05D7\u05E8\u05D5 \u05E7\u05D5\u05D1\u05E5 \u05DC\u05D4\u05E2\u05DC\u05D0\u05D4.");
  if (file.size > 4e6) return void (status.textContent = "\u05D4\u05E7\u05D5\u05D1\u05E5 \u05D2\u05D3\u05D5\u05DC \u05DE\u05D3\u05D9. \u05D4\u05D2\u05D5\u05D3\u05DC \u05D4\u05DE\u05E8\u05D1\u05D9 \u05D4\u05D5\u05D0 4 MB.");
  button.disabled = true;
  status.textContent = "\u05DE\u05E2\u05DC\u05D9\u05DD \u05D5\u05E9\u05D5\u05DE\u05E8\u05D9\u05DD \u05D0\u05EA \u05D4\u05DE\u05E1\u05DE\u05DA\u2026";
  try {
    const response = await fetch("/api/admin-document", { method: "POST", credentials: "same-origin", body });
    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      status.textContent = result.error === "unsupported_file" ? "\u05E0\u05D9\u05EA\u05DF \u05DC\u05D4\u05E2\u05DC\u05D5\u05EA \u05E8\u05E7 PDF, PNG \u05D0\u05D5 JPG \u05EA\u05E7\u05D9\u05E0\u05D9\u05DD." : result.error === "upload_limit" ? "\u05D4\u05D2\u05E2\u05EA\u05DD \u05DC\u05DE\u05D2\u05D1\u05DC\u05EA \u05D4\u05E2\u05DC\u05D0\u05D5\u05EA \u05D6\u05DE\u05E0\u05D9\u05EA. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1 \u05DE\u05D0\u05D5\u05D7\u05E8 \u05D9\u05D5\u05EA\u05E8." : result.error === "file_too_large" ? "\u05D4\u05E7\u05D5\u05D1\u05E5 \u05D2\u05D3\u05D5\u05DC \u05DE\u05D3\u05D9. \u05D4\u05D2\u05D5\u05D3\u05DC \u05D4\u05DE\u05E8\u05D1\u05D9 \u05D4\u05D5\u05D0 4 MB." : "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05E9\u05DE\u05D5\u05E8 \u05D0\u05EA \u05D4\u05DE\u05E1\u05DE\u05DA. \u05D1\u05D3\u05E7\u05D5 \u05D0\u05EA \u05D4\u05E4\u05E8\u05D8\u05D9\u05DD \u05D5\u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.";
      return;
    }
    await refreshAdmin();
    document.getElementById("documents")?.scrollIntoView({ block: "start" });
    showToast("\u05D4\u05DE\u05E1\u05DE\u05DA \u05E0\u05E9\u05DE\u05E8 \u05D1\u05D4\u05E6\u05DC\u05D7\u05D4.");
  } catch {
    status.textContent = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D4\u05E2\u05DC\u05D5\u05EA \u05D0\u05EA \u05D4\u05E7\u05D5\u05D1\u05E5 \u05DB\u05E8\u05D2\u05E2. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.";
  } finally {
    button.disabled = false;
  }
}
async function submitRecord(event, defaultAction) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector(".form-status");
  const button = form.querySelector('button[type="submit"]');
  const data = Object.fromEntries(new FormData(form));
  const action = defaultAction === "createClient" && editingClientId ? "updateClient" : defaultAction === "createProject" && editingProjectId ? "updateProject" : defaultAction;
  if (action === "updateClient") data.id = editingClientId;
  if (action === "updateProject") data.id = editingProjectId;
  if (action === "addEntry" && data.category === "project" && !data.project_id) {
    status.textContent = "\u05D1\u05D7\u05E8\u05D5 \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05E2\u05D1\u05D5\u05E8 \u05EA\u05E0\u05D5\u05E2\u05D4 \u05E9\u05DC \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05DC\u05E7\u05D5\u05D7.";
    form.elements.namedItem("project_id")?.focus();
    return;
  }
  button.disabled = true;
  status.textContent = "\u05E9\u05D5\u05DE\u05E8\u05D9\u05DD\u2026";
  const result = await saveRecord({ action, ...data });
  if (!result.ok) {
    status.textContent = result.body.error === "share_exceeds_100" ? "\u05E1\u05DA \u05D4\u05D0\u05D7\u05D5\u05D6\u05D9\u05DD \u05D1\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05DC\u05D0 \u05D9\u05DB\u05D5\u05DC \u05DC\u05E2\u05D1\u05D5\u05E8 100%." : result.body.error === "invalid_entry" ? "\u05D1\u05D3\u05E7\u05D5 \u05D0\u05EA \u05E1\u05DB\u05D5\u05DD, \u05EA\u05D0\u05E8\u05D9\u05DA \u05D5\u05E4\u05E8\u05D8\u05D9 \u05D4\u05EA\u05E0\u05D5\u05E2\u05D4." : "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05E9\u05DE\u05D5\u05E8 \u05DB\u05E8\u05D2\u05E2. \u05D1\u05D3\u05E7\u05D5 \u05D0\u05EA \u05D4\u05E4\u05E8\u05D8\u05D9\u05DD \u05D5\u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.";
    button.disabled = false;
    return;
  }
  const sectionId = form.closest(".workspace-section")?.id || "overview";
  editingClientId = null;
  editingProjectId = null;
  await refreshAdmin();
  document.getElementById(sectionId)?.scrollIntoView({ block: "start" });
  showToast("\u05D4\u05E0\u05EA\u05D5\u05E0\u05D9\u05DD \u05E0\u05E9\u05DE\u05E8\u05D5 \u05D1\u05D4\u05E6\u05DC\u05D7\u05D4.");
}
function editClient(value) {
  const client = adminData?.clients?.find((item) => String(item.id) === String(value));
  const form = document.getElementById("client-form");
  if (!client || !form) return;
  editingClientId = client.id;
  for (const key of ["name", "company", "contact", "notes"]) form.elements.namedItem(key).value = client[key] || "";
  document.getElementById("client-form-title").textContent = "\u05E2\u05E8\u05D9\u05DB\u05EA \u05DC\u05E7\u05D5\u05D7";
  document.getElementById("client-cancel").hidden = false;
  form.scrollIntoView({ block: "center", behavior: "smooth" });
  form.elements.namedItem("name").focus();
}
function editProject(value) {
  const project = adminData?.projects?.find((item) => String(item.id) === String(value));
  const form = document.getElementById("project-form");
  if (!project || !form) return;
  editingProjectId = project.id;
  for (const key of ["name", "client_id", "status", "budget_ils", "notes"]) form.elements.namedItem(key).value = project[key] ?? "";
  document.getElementById("project-form-title").textContent = "\u05E2\u05E8\u05D9\u05DB\u05EA \u05E4\u05E8\u05D5\u05D9\u05E7\u05D8";
  document.getElementById("project-cancel").hidden = false;
  form.scrollIntoView({ block: "center", behavior: "smooth" });
  form.elements.namedItem("name").focus();
}
function resetEdit(kind) {
  const form = document.getElementById(`${kind}-form`);
  if (!form) return;
  form.reset();
  if (kind === "client") editingClientId = null;
  else editingProjectId = null;
  document.getElementById(`${kind}-form-title`).textContent = kind === "client" ? "\u05DC\u05E7\u05D5\u05D7 \u05D7\u05D3\u05E9" : "\u05E4\u05E8\u05D5\u05D9\u05E7\u05D8 \u05D7\u05D3\u05E9";
  document.getElementById(`${kind}-cancel`).hidden = true;
  form.querySelector(".form-status").textContent = "";
}
function showToast(message) {
  toast.textContent = message;
  toast.classList.add("is-visible");
  setTimeout(() => toast.classList.remove("is-visible"), 4e3);
}
async function submitLogin(event) {
  event.preventDefault();
  await identityReady;
  const form = event.currentTarget;
  const status = form.querySelector(".form-status");
  if (!identity) return void (status.textContent = "\u05E9\u05D9\u05E8\u05D5\u05EA \u05D4\u05D4\u05EA\u05D7\u05D1\u05E8\u05D5\u05EA \u05D0\u05D9\u05E0\u05D5 \u05D6\u05DE\u05D9\u05DF \u05DB\u05E8\u05D2\u05E2.");
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  status.textContent = "\u05DE\u05EA\u05D7\u05D1\u05E8\u05D9\u05DD\u2026";
  try {
    await identity.login(form.querySelector("#login-email").value.trim(), form.querySelector("#login-password").value);
    await refreshAdmin();
  } catch {
    status.textContent = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D4\u05EA\u05D7\u05D1\u05E8. \u05D1\u05D3\u05E7\u05D5 \u05D0\u05EA \u05D4\u05E4\u05E8\u05D8\u05D9\u05DD \u05D5\u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.";
  } finally {
    button.disabled = false;
  }
}
async function submitPassword(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const password = form.querySelector("#new-password").value;
  const status = form.querySelector(".form-status");
  if (password !== form.querySelector("#confirm-password").value) return void (status.textContent = "\u05D4\u05E1\u05D9\u05E1\u05DE\u05D0\u05D5\u05EA \u05D0\u05D9\u05E0\u05DF \u05D6\u05D4\u05D5\u05EA.");
  try {
    if (identityCallback?.type === "invite") await identity.acceptInvite(identityCallback.token, password);
    else await identity.updateUser({ password });
    identityCallback = null;
    history.replaceState({}, "", "/admin");
    await refreshAdmin();
  } catch {
    status.textContent = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D4\u05E9\u05DC\u05D9\u05DD \u05D0\u05EA \u05D4\u05E4\u05E2\u05D5\u05DC\u05D4. \u05D9\u05D9\u05EA\u05DB\u05DF \u05E9\u05D4\u05E7\u05D9\u05E9\u05D5\u05E8 \u05E4\u05D2 \u05EA\u05D5\u05E7\u05E3.";
  }
}
async function startMfa() {
  const button = document.querySelector("#mfa-start");
  const status = document.querySelector(".mfa-card .form-status");
  button.disabled = true;
  status.textContent = "\u05DE\u05DB\u05D9\u05E0\u05D9\u05DD \u05DE\u05E4\u05EA\u05D7 \u05DC\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D9\u05EA \u05D4\u05D0\u05D9\u05DE\u05D5\u05EA\u2026";
  try {
    const response = await fetch("/api/admin-auth", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "start" }) });
    if (!response.ok) throw new Error("MFA setup failed");
    mfaSetup = await response.json();
    render();
  } catch {
    status.textContent = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D4\u05EA\u05D7\u05D9\u05DC \u05D0\u05EA \u05D4\u05D4\u05D2\u05D3\u05E8\u05D4. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1 \u05D1\u05E2\u05D5\u05D3 \u05DB\u05DE\u05D4 \u05D3\u05E7\u05D5\u05EA.";
    button.disabled = false;
  }
}
async function submitMfa(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector(".form-status");
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  status.textContent = "\u05DE\u05D0\u05DE\u05EA\u05D9\u05DD \u05D0\u05EA \u05D4\u05E7\u05D5\u05D3\u2026";
  try {
    const response = await fetch("/api/admin-auth", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "verify", code: form.querySelector("#mfa-code").value.trim() }) });
    if (!response.ok) {
      status.textContent = response.status === 429 ? "\u05E0\u05D9\u05E1\u05D9\u05D5\u05E0\u05D5\u05EA \u05E8\u05D1\u05D9\u05DD \u05DE\u05D3\u05D9. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1 \u05D1\u05E2\u05D5\u05D3 15 \u05D3\u05E7\u05D5\u05EA." : "\u05D4\u05E7\u05D5\u05D3 \u05E9\u05D2\u05D5\u05D9 \u05D0\u05D5 \u05E9\u05DB\u05D1\u05E8 \u05E0\u05E2\u05E9\u05D4 \u05D1\u05D5 \u05E9\u05D9\u05DE\u05D5\u05E9.";
      return;
    }
    const result = await response.json();
    mfaSetup = null;
    if (Array.isArray(result.recoveryCodes) && result.recoveryCodes.length) {
      mfaRecoveryCodes = result.recoveryCodes;
      render();
    } else await refreshAdmin();
  } catch {
    status.textContent = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D0\u05DE\u05EA \u05D0\u05EA \u05D4\u05E7\u05D5\u05D3 \u05DB\u05E8\u05D2\u05E2. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.";
  } finally {
    button.disabled = false;
  }
}
async function regenerateRecovery(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector(".form-status");
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  status.textContent = "\u05D9\u05D5\u05E6\u05E8\u05D9\u05DD \u05E7\u05D5\u05D3\u05D9 \u05D2\u05D9\u05D1\u05D5\u05D9 \u05D7\u05D3\u05E9\u05D9\u05DD\u2026";
  try {
    const response = await fetch("/api/admin-auth", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "regenerateRecovery", code: form.elements.namedItem("code").value.trim() })
    });
    if (!response.ok) {
      status.textContent = response.status === 429 ? "\u05E0\u05D9\u05E1\u05D9\u05D5\u05E0\u05D5\u05EA \u05E8\u05D1\u05D9\u05DD \u05DE\u05D3\u05D9. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1 \u05D1\u05E2\u05D5\u05D3 15 \u05D3\u05E7\u05D5\u05EA." : "\u05D4\u05E7\u05D5\u05D3 \u05E9\u05D2\u05D5\u05D9 \u05D0\u05D5 \u05E9\u05DB\u05D1\u05E8 \u05E0\u05E2\u05E9\u05D4 \u05D1\u05D5 \u05E9\u05D9\u05DE\u05D5\u05E9. \u05D7\u05DB\u05D5 \u05DC\u05E7\u05D5\u05D3 \u05D4\u05D1\u05D0 \u05D1\u05D0\u05E4\u05DC\u05D9\u05E7\u05E6\u05D9\u05D4.";
      return;
    }
    const result = await response.json();
    mfaRecoveryCodes = result.recoveryCodes;
    render();
  } catch {
    status.textContent = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05D9\u05E6\u05D5\u05E8 \u05E7\u05D5\u05D3\u05D9\u05DD \u05DB\u05E8\u05D2\u05E2. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.";
  } finally {
    button.disabled = false;
  }
}
async function submitInvite(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector(".form-status");
  const button = form.querySelector('button[type="submit"]');
  const data = Object.fromEntries(new FormData(form));
  button.disabled = true;
  status.textContent = "\u05E9\u05D5\u05DC\u05D7\u05D9\u05DD \u05E7\u05D9\u05E9\u05D5\u05E8 \u05D4\u05E6\u05D8\u05E8\u05E4\u05D5\u05EA\u2026";
  try {
    const response = await fetch("/api/admin-invite", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify(data) });
    if (!response.ok) {
      status.textContent = response.status === 409 ? "\u05D4\u05DB\u05EA\u05D5\u05D1\u05EA \u05D4\u05D6\u05D5 \u05DB\u05D1\u05E8 \u05DE\u05E9\u05D5\u05D9\u05DB\u05EA \u05DC\u05E6\u05D5\u05D5\u05EA." : response.status === 429 ? "\u05E0\u05E9\u05DC\u05D7\u05D5 \u05D4\u05D6\u05DE\u05E0\u05D5\u05EA \u05E8\u05D1\u05D5\u05EA. \u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1 \u05DE\u05D0\u05D5\u05D7\u05E8 \u05D9\u05D5\u05EA\u05E8." : "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05E9\u05DC\u05D5\u05D7 \u05D0\u05EA \u05D4\u05D4\u05D6\u05DE\u05E0\u05D4. \u05D1\u05D3\u05E7\u05D5 \u05D0\u05EA \u05D4\u05D4\u05D2\u05D3\u05E8\u05D5\u05EA \u05D5\u05E0\u05E1\u05D5 \u05E9\u05D5\u05D1.";
      return;
    }
    await refreshAdmin();
    showToast("\u05E7\u05D9\u05E9\u05D5\u05E8 \u05D4\u05E6\u05D8\u05E8\u05E4\u05D5\u05EA \u05E0\u05E9\u05DC\u05D7 \u05D1\u05D4\u05E6\u05DC\u05D7\u05D4.");
  } catch {
    status.textContent = "\u05DC\u05D0 \u05D4\u05E6\u05DC\u05D7\u05E0\u05D5 \u05DC\u05E9\u05DC\u05D5\u05D7 \u05D0\u05EA \u05D4\u05D4\u05D6\u05DE\u05E0\u05D4 \u05DB\u05E8\u05D2\u05E2.";
  } finally {
    button.disabled = false;
  }
}
render();
identityReady.then(() => {
  render();
});
