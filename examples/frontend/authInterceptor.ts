import { AxiosInstance } from 'axios';
import { AuthService } from './authService';

export const setupInterceptors = (api: AxiosInstance) => {
  const authService = AuthService.getInstance();

  api.interceptors.request.use(
    (config) => {
      const token = authService.getAccessToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    },
    (error) => Promise.reject(error)
  );

  api.interceptors.response.use(
    (response) => response,
    async (error) => {
      if (error.response?.status === 401) {
        try {
          await authService.refreshToken();
          return api(error.config);
        } catch (refreshError) {
          authService.logout();
          throw refreshError;
        }
      }
      return Promise.reject(error);
    }
  );
}; 