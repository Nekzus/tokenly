import axios from 'axios';
import { Tokenly } from '../../src/tokenManager';

const tokenly = new Tokenly();
const api = axios.create({
  baseURL: '/api',
  withCredentials: true
});

export class AuthService {
  private static instance: AuthService;
  private accessToken: string | null = null;

  static getInstance(): AuthService {
    if (!AuthService.instance) {
      AuthService.instance = new AuthService();
    }
    return AuthService.instance;
  }

  async login(email: string, password: string) {
    try {
      const response = await api.post('/auth/login', { email, password });
      this.accessToken = response.data.accessToken;
      tokenly.setToken(this.accessToken);
      return response.data;
    } catch (error) {
      throw new Error('Login failed');
    }
  }

  async refreshToken() {
    try {
      const response = await api.post('/auth/refresh');
      this.accessToken = response.data.accessToken;
      tokenly.setToken(this.accessToken);
      return response.data;
    } catch (error) {
      throw new Error('Token refresh failed');
    }
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  logout() {
    this.accessToken = null;
    tokenly.clearToken();
  }
} 