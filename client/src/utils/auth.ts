import { JwtPayload, jwtDecode } from 'jwt-decode';

class AuthService {
  // Get the decoded token payload
  getProfile(): JwtPayload | null {
    const token = this.getToken();
    if (token) {
      return jwtDecode<JwtPayload>(token); // Decode the token
    }
    return null;
  }

  // Check if the user is logged in
  loggedIn(): boolean {
    const token = this.getToken();
    return !!token && !this.isTokenExpired(token); // Token exists and is not expired
  }

  // Check if the token is expired
  isTokenExpired(token: string): boolean {
    try {
      const decoded = jwtDecode<JwtPayload>(token);
      if (decoded.exp && decoded.exp < Date.now() / 1000) {
        return true; // Token is expired
      }
      return false; // Token is valid
    } catch (err) {
      return true; // Invalid token
    }
  }

  // Get the token from localStorage
  getToken(): string {
    return localStorage.getItem('id_token') || ''; // Return the token or an empty string
  }

  // Store the token in localStorage and redirect to the home page
  login(idToken: string): void {
    localStorage.setItem('id_token', idToken); // Save the token
    window.location.assign('/'); // Redirect to the home page
  }

  // Remove the token from localStorage and redirect to the login page
  logout(): void {
    localStorage.removeItem('id_token'); // Clear the token
    window.location.assign('/login'); // Redirect to the login page
  }
}

export default new AuthService();