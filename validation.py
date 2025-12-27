"""

This module handles all input validation including:
 Password strength checking (length, special characters)
 Username validation
"""

import string


def check_password_strength(password):
    """
    Validate password meets security requirements.
    
    Requirements:
        Minimum 8 characters
        At least one special character 
    
    """
    # Check minimum length
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    # Check for special character
    if not any(char in string.punctuation for char in password):
        return False, "Password must contain at least one special character (!@#$%)."
    
    return True, "Password accepted."