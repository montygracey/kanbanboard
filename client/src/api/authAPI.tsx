import { UserLogin } from "../interfaces/UserLogin";

const login = async (userInfo: UserLogin) => {
  try {
    // 1. Make a POST request to the login route
    const response = await fetch('/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userInfo), // Send username and password
    });

    // 2. Check if the response is successful
    if (!response.ok) {
      // Handle error responses (e.g., invalid credentials)
      const errorData = await response.json();
      throw new Error(errorData.message || 'Login failed. Please try again.');
    }

    // 3. Extract the JWT token from the response
    const data = await response.json();
    return data.token; // Return the token
  } catch (error) {
    // 4. Handle network errors or other exceptions
    console.error('Error during login:', error);
    throw error; // Re-throw the error for the caller to handle
  }
};

export { login };