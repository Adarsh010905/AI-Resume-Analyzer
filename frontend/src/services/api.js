const BASE_URL = import.meta.env.VITE_API_URL || '';

async function request(endpoint, options = {}, isFormData = false) {
  const url = `${BASE_URL}${endpoint}`;
  const accessToken = localStorage.getItem('access_token');
  const headers = {};

  if (!isFormData) {
    headers['Content-Type'] = 'application/json';
  }

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const config = {
    ...options,
    headers: { ...headers, ...options.headers },
  };

  const isAuthEndpoint =
    endpoint.includes('/api/auth/login') ||
    endpoint.includes('/api/auth/register') ||
    endpoint.includes('/api/auth/token/refresh');

  let response;
  try {
    response = await fetch(url, config);
  } catch (networkError) {
    throw new Error('Network error: Could not connect to the server.');
  }

  if (response.status === 401 && !isAuthEndpoint) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      const retryHeaders = { ...headers, ...options.headers };
      retryHeaders['Authorization'] = `Bearer ${localStorage.getItem('access_token')}`;
      try {
        const retryResponse = await fetch(url, { ...config, headers: retryHeaders });
        return await handleResponse(retryResponse);
      } catch (networkError) {
        throw new Error('Network error: Could not connect to the server.');
      }
    } else {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('user');
      window.location.href = '/login';
      return;
    }
  }

  return await handleResponse(response);
}

async function handleResponse(response) {
  if (response.status === 204 || response.headers.get('content-length') === '0') {
    if (!response.ok) throw new Error('Request failed');
    return {};
  }

  let data;
  try {
    data = await response.json();
  } catch {
    if (response.ok) return {};
    data = { message: 'Server returned an unexpected response' };
  }

  if (!response.ok) {
    const errorMessage = extractErrorMessage(data);
    const error = new Error(errorMessage);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

function extractErrorMessage(data) {
  if (typeof data === 'string') return data;
  if (data.error) return data.error;
  if (data.detail) return data.detail;
  if (data.message) return data.message;
  if (data.non_field_errors) return data.non_field_errors[0];

  const fieldErrors = [];
  for (const [field, errors] of Object.entries(data)) {
    if (Array.isArray(errors)) {
      fieldErrors.push(`${field}: ${errors.join(', ')}`);
    }
  }
  if (fieldErrors.length > 0) return fieldErrors.join(' | ');
  return 'An unexpected error occurred';
}

async function refreshAccessToken() {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) return false;

  try {
    const response = await fetch(`${BASE_URL}/api/auth/token/refresh/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh: refreshToken }),
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('access_token', data.access);
      return true;
    }
  } catch (e) {
    console.error('Token refresh failed:', e);
  }

  return false;
}

const api = {
  auth: {
    register: (email, firstName, lastName, password, password2) =>
      request('/api/auth/register/', {
        method: 'POST',
        body: JSON.stringify({ email, first_name: firstName, last_name: lastName, password, password2 }),
      }),

    login: async (email, password) => {
      const data = await request('/api/auth/login/', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      if (data.tokens) {
        localStorage.setItem('access_token', data.tokens.access);
        localStorage.setItem('refresh_token', data.tokens.refresh);
        localStorage.setItem('user', JSON.stringify(data.user));
      }
      return data;
    },

    logout: async () => {
      const refreshToken = localStorage.getItem('refresh_token');
      try {
        await request('/api/auth/logout/', {
          method: 'POST',
          body: JSON.stringify({ refresh: refreshToken }),
        });
      } finally {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
      }
    },

    getProfile: () => request('/api/auth/profile/'),

    updateProfile: (data) =>
      request('/api/auth/profile/', { method: 'PATCH', body: JSON.stringify(data) }),

    changePassword: (oldPassword, newPassword, newPassword2) =>
      request('/api/auth/change-password/', {
        method: 'POST',
        body: JSON.stringify({ old_password: oldPassword, new_password: newPassword, new_password2: newPassword2 }),
      }),
  },

  analyzer: {
    analyze: (formData) =>
      request('/api/analyzer/analyze/', { method: 'POST', body: formData }, true),

    getHistory: (page = 1) => request(`/api/analyzer/history/?page=${page}`),

    getAnalysis: (id) => request(`/api/analyzer/history/${id}/`),

    deleteAnalysis: (id) => request(`/api/analyzer/history/${id}/`, { method: 'DELETE' }),

    getStats: () => request('/api/analyzer/stats/'),
  },
};

export default api;
