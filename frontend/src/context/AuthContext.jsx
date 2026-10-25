import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('user');
      const token = localStorage.getItem('access_token');
      return token && stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    const accessToken = localStorage.getItem('access_token');
    const storedUser = localStorage.getItem('user');

    if (accessToken && storedUser) {
      try {
        const profileData = await api.auth.getProfile();
        setUser(profileData);
        localStorage.setItem('user', JSON.stringify(profileData));
      } catch (err) {
        // If 401, tokens were expired and refresh failed
        if (err.status === 401) {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('user');
          setUser(null);
        }
      }
    } else {
      setUser(null);
    }
    setIsLoading(false);
  };

  const login = useCallback(async (email, password) => {
    const data = await api.auth.login(email, password);
    setUser(data.user);
    return data;
  }, []);

  const register = useCallback(async (email, firstName, lastName, password, password2) => {
    const data = await api.auth.register(email, firstName, lastName, password, password2);
    if (data.tokens) {
      localStorage.setItem('access_token', data.tokens.access);
      localStorage.setItem('refresh_token', data.tokens.refresh);
      localStorage.setItem('user', JSON.stringify(data.user));
      setUser(data.user);
    }
    return data;
  }, []);

  const logout = useCallback(async () => {
    await api.auth.logout();
    setUser(null);
  }, []);

  const updateUser = useCallback((updatedUser) => {
    setUser(updatedUser);
    localStorage.setItem('user', JSON.stringify(updatedUser));
  }, []);

  return (
    <AuthContext.Provider value={{
      user,
      isLoading,
      isLoggedIn: !!user,
      login,
      register,
      logout,
      updateUser,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
