# CSRF Protection Implementation Guide

## Backend Implementation Complete ✅

### What has been implemented:

1. **CSRF Middleware** (`middleware/csrfProtection.js`)

   - Conditional CSRF protection that skips safe routes
   - Cookie-based CSRF token storage
   - Error handling for invalid tokens

2. **CSRF Routes** (`routes/csrfRoute.js`)

   - `/api/csrf/token` - Get CSRF token
   - `/api/csrf/test` - Test CSRF protection

3. **CSRF Utilities** (`utils/csrfUtils.js`)

   - Helper functions for token management
   - Response data enhancement

4. **Server Configuration** (`server.js`)
   - CSRF middleware integration
   - CORS headers updated to include `X-CSRF-Token`
   - Error handling middleware

### API Endpoints Added:

- `GET /api/csrf-token` - Get CSRF token (no protection needed)
- `GET /api/csrf/token` - Alternative CSRF token endpoint
- `POST /api/csrf/test` - Test CSRF protection

## Frontend Changes Required 📋

### 1. **CSRF Token Management**

Create a CSRF service/utility:

```javascript
// utils/csrfService.js
class CSRFService {
  constructor() {
    this.token = null;
  }

  async getToken() {
    if (!this.token) {
      await this.refreshToken();
    }
    return this.token;
  }

  async refreshToken() {
    try {
      const response = await fetch("https://localhost:4000/api/csrf-token", {
        method: "GET",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
      });

      const data = await response.json();
      if (data.success) {
        this.token = data.csrfToken;
        return this.token;
      }
      throw new Error("Failed to get CSRF token");
    } catch (error) {
      console.error("CSRF token fetch error:", error);
      throw error;
    }
  }

  clearToken() {
    this.token = null;
    // Clear from localStorage/sessionStorage if stored there
    localStorage.removeItem("csrfToken");
    sessionStorage.removeItem("csrfToken");
    console.log("🧹 CSRF token cleared");
  }

  // Force clear and get new token (useful after logout)
  async resetToken() {
    this.clearToken();
    return await this.refreshToken();
  }
}

export const csrfService = new CSRFService();
```

### 2. **HTTP Client Updates**

#### For Axios users:

```javascript
// utils/httpClient.js
import axios from "axios";
import { csrfService } from "./csrfService.js";

const httpClient = axios.create({
  baseURL: "https://localhost:4000",
  withCredentials: true,
});

// Request interceptor to add CSRF token
httpClient.interceptors.request.use(async (config) => {
  // Only add CSRF token for state-changing methods
  if (["post", "put", "patch", "delete"].includes(config.method)) {
    try {
      const csrfToken = await csrfService.getToken();
      config.headers["X-CSRF-Token"] = csrfToken;
    } catch (error) {
      console.error("Failed to get CSRF token:", error);
    }
  }
  return config;
});

// Response interceptor to handle CSRF errors
httpClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (
      error.response?.status === 403 &&
      error.response?.data?.error === "CSRF_TOKEN_INVALID"
    ) {
      // Clear the invalid token and retry
      csrfService.clearToken();
      try {
        await csrfService.refreshToken();
        // Retry the original request
        const originalRequest = error.config;
        originalRequest.headers["X-CSRF-Token"] = await csrfService.getToken();
        return httpClient.request(originalRequest);
      } catch (retryError) {
        console.error("CSRF token retry failed:", retryError);
      }
    }
    return Promise.reject(error);
  }
);

export default httpClient;
```

#### For Fetch API users:

```javascript
// utils/fetchWithCSRF.js
import { csrfService } from "./csrfService.js";

export async function fetchWithCSRF(url, options = {}) {
  const method = options.method || "GET";

  // For state-changing methods, add CSRF token
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase())) {
    try {
      const csrfToken = await csrfService.getToken();
      options.headers = {
        ...options.headers,
        "X-CSRF-Token": csrfToken,
      };
    } catch (error) {
      console.error("Failed to get CSRF token:", error);
      throw error;
    }
  }

  // Ensure credentials are included
  options.credentials = "include";

  try {
    const response = await fetch(url, options);

    // Handle CSRF token errors
    if (response.status === 403) {
      const errorData = await response.json();
      if (errorData.error === "CSRF_TOKEN_INVALID") {
        csrfService.clearToken();
        // Retry with new token
        const newToken = await csrfService.refreshToken();
        options.headers["X-CSRF-Token"] = newToken;
        return fetch(url, options);
      }
    }

    return response;
  } catch (error) {
    console.error("Fetch with CSRF error:", error);
    throw error;
  }
}
```

### 3. **React Hook for CSRF (if using React)**

```javascript
// hooks/useCSRF.js
import { useState, useEffect } from "react";
import { csrfService } from "../utils/csrfService.js";

export function useCSRF() {
  const [csrfToken, setCsrfToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refreshToken = async () => {
    try {
      setLoading(true);
      setError(null);
      const token = await csrfService.refreshToken();
      setCsrfToken(token);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshToken();
  }, []);

  return {
    csrfToken,
    loading,
    error,
    refreshToken,
  };
}
```

### 4. **Form Handling Updates**

#### For HTML forms:

```javascript
// Add CSRF token to forms
const form = document.getElementById("myForm");
const csrfToken = await csrfService.getToken();

// Add hidden input
const csrfInput = document.createElement("input");
csrfInput.type = "hidden";
csrfInput.name = "_csrf";
csrfInput.value = csrfToken;
form.appendChild(csrfInput);
```

#### For React forms:

```jsx
// components/ProtectedForm.jsx
import { useCSRF } from "../hooks/useCSRF.js";

function ProtectedForm({ onSubmit, children }) {
  const { csrfToken, loading } = useCSRF();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!csrfToken) return;

    const formData = new FormData(e.target);
    formData.append("_csrf", csrfToken);

    await onSubmit(formData);
  };

  if (loading) return <div>Loading...</div>;

  return (
    <form onSubmit={handleSubmit}>
      <input type="hidden" name="_csrf" value={csrfToken} />
      {children}
    </form>
  );
}
```

### 5. **State Management Integration**

#### For Redux/Zustand stores:

```javascript
// store/csrfSlice.js (Redux Toolkit)
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { csrfService } from "../utils/csrfService.js";

export const fetchCSRFToken = createAsyncThunk("csrf/fetchToken", async () => {
  return await csrfService.refreshToken();
});

const csrfSlice = createSlice({
  name: "csrf",
  initialState: {
    token: null,
    loading: false,
    error: null,
  },
  reducers: {
    clearToken: (state) => {
      state.token = null;
      csrfService.clearToken();
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchCSRFToken.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchCSRFToken.fulfilled, (state, action) => {
        state.loading = false;
        state.token = action.payload;
      })
      .addCase(fetchCSRFToken.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      });
  },
});

export const { clearToken } = csrfSlice.actions;
export default csrfSlice.reducer;
```

### 6. **Logout Implementation**

#### Backend Logout (✅ Already Implemented):

```javascript
// POST /api/user/logout
// Clears CSRF token and session cookies
```

#### Frontend Logout Function:

```javascript
// utils/authService.js
import { csrfService } from "./csrfService.js";

export const logout = async () => {
  try {
    // Get CSRF token for logout request
    const csrfToken = await csrfService.getToken();

    // Call backend logout endpoint
    const response = await fetch("https://localhost:4000/api/user/logout", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
        Authorization: `Bearer ${localStorage.getItem("authToken")}`, // if using JWT
      },
    });

    const data = await response.json();

    if (data.success) {
      // Clear CSRF token from service
      csrfService.clearToken();

      // Clear all auth-related data
      localStorage.removeItem("authToken");
      localStorage.removeItem("userData");
      sessionStorage.clear();

      // Force refresh CSRF token for next session
      await csrfService.refreshToken();

      console.log("✅ Logout successful");
      return true;
    } else {
      throw new Error(data.message);
    }
  } catch (error) {
    console.error("❌ Logout error:", error);
    // Even if logout fails, clear local data for security
    csrfService.clearToken();
    localStorage.clear();
    sessionStorage.clear();
    return false;
  }
};
```

#### React Logout Hook:

```jsx
// hooks/useAuth.js
import { useState } from "react";
import { logout } from "../utils/authService.js";

export const useAuth = () => {
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const handleLogout = async () => {
    setIsLoggingOut(true);
    try {
      const success = await logout();
      if (success) {
        // Redirect to login page
        window.location.href = "/login";
        // Or use your router
        // navigate('/login');
      }
    } catch (error) {
      console.error("Logout failed:", error);
      // Force redirect even on error for security
      window.location.href = "/login";
    } finally {
      setIsLoggingOut(false);
    }
  };

  return { handleLogout, isLoggingOut };
};
```

#### Usage in Components:

```jsx
// components/Header.jsx
import { useAuth } from "../hooks/useAuth.js";

const Header = () => {
  const { handleLogout, isLoggingOut } = useAuth();

  return (
    <div>
      <button
        onClick={handleLogout}
        disabled={isLoggingOut}
        className="logout-btn"
      >
        {isLoggingOut ? "Logging out..." : "Logout"}
      </button>
    </div>
  );
};
```

### 7. **App Initialization**

```javascript
// App initialization
import { csrfService } from "./utils/csrfService.js";

// Initialize CSRF token when app starts
document.addEventListener("DOMContentLoaded", async () => {
  try {
    await csrfService.refreshToken();
    console.log("CSRF token initialized");
  } catch (error) {
    console.error("Failed to initialize CSRF token:", error);
  }
});
```

### 7. **Error Handling**

```javascript
// Global error handler for CSRF errors
window.addEventListener("unhandledrejection", (event) => {
  if (event.reason?.response?.data?.error === "CSRF_TOKEN_INVALID") {
    // Show user-friendly message
    alert("Security token expired. Please refresh the page.");
    // Or redirect to refresh
    window.location.reload();
  }
});
```

## Testing Your Implementation 🧪

### Backend Testing:

```bash
# Test CSRF token generation
curl -X GET https://localhost:4000/api/csrf-token \
  -H "Content-Type: application/json" \
  -c cookies.txt

# Test CSRF protection (should fail without token)
curl -X POST https://localhost:4000/api/csrf/test \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}' \
  -b cookies.txt

# Test with valid token
curl -X POST https://localhost:4000/api/csrf/test \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_TOKEN_HERE" \
  -d '{"test": "data"}' \
  -b cookies.txt
```

### Frontend Testing:

1. Open browser dev tools
2. Try making requests without CSRF token (should fail)
3. Get token and make request with token (should succeed)
4. Verify cookie is set properly

## Security Notes 🔒

1. **HTTPS Only**: CSRF protection works best with HTTPS
2. **SameSite Cookies**: Configured for additional protection
3. **Token Rotation**: Tokens expire after 1 hour
4. **Error Handling**: Graceful degradation for token failures

## Troubleshooting 🔧

### Common Issues:

1. **Token not being sent**: Check if credentials are included in requests
2. **CORS errors**: Ensure `X-CSRF-Token` is in allowed headers
3. **Token expired**: Implement automatic retry logic
4. **Cookie issues**: Check SameSite and Secure settings
