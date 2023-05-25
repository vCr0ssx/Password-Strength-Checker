# Password Strength Checker 
import getpass
from string import ascii_lowercase, ascii_uppercase, digits, punctuation
from zxcvbn import zxcvbn
from datetime import datetime

# Define password strength categories and their weights
CATEGORIES = {
    'length': {'name': 'length', 'weight': 4},
    'lowercase': {'name': 'lowercase', 'weight': 2},
    'uppercase': {'name': 'uppercase', 'weight': 3},
    'digits': {'name': 'digits', 'weight': 3},
    'symbols': {'name': 'symbols', 'weight': 4},
    'common': {'name': 'common', 'weight': -4},
    'dictionary': {'name': 'dictionary', 'weight': -2},
    'age': {'name': 'age', 'weight': -2}
}

def read_password_list(filename: str) -> set:
    """Read a list of passwords from a file and return as a set."""
    with open(filename) as f:
        return {line.strip().lower() for line in f}

# Load common passwords and dictionary words
COMMON_PASSWORDS = read_password_list('common_passwords.txt')
DICTIONARY_WORDS = read_password_list('dictionary_words.txt')

MAX_PASSWORD_AGE_DAYS = 90 # Maximum password age in days

def calculate_password_strength(password, creation_date=None):
    feedback = []
    score = 0
    
    # Check password length and character classes
    if len(password) >= 8 and any(char_class in password for char_class in [ascii_lowercase, ascii_uppercase, digits, punctuation]):
        if password.islower() or password.isupper():
            feedback.append('Your password should contain a mix of uppercase and lowercase letters.')
            score += sum(cat['weight'] for cat in CATEGORIES.values())
        else:
            score += sum(cat['weight'] for cat in CATEGORIES.values() if cat['name'] != 'common' and cat['name'] != 'dictionary' and cat['name'] != 'leaked')
    else:
        feedback.append('Your password should be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one symbol.')
        score += sum(cat['weight'] for cat in CATEGORIES.values() if cat['name'] in ['length', 'lowercase', 'uppercase', 'digits', 'symbols'])
    
    # Check if password is a common
    if zxcvbn(password)['guesses_log10'] < 4:
        feedback.append('Your password is too common or predictable.')
        score += CATEGORIES['common']['weight']
    
    # Check if password is a dictionary word
    match_sequence = zxcvbn(password)['sequence']
    if any(match['dictionary_name'] for match in match_sequence):
        feedback.append('Your password is a dictionary word.')
        score += CATEGORIES['dictionary']['weight']
    
    # Calculate score percentage
    score_percent = round(score / sum(cat['weight'] for cat in CATEGORIES.values()) * 100)

    # Factor in password age
    if creation_date is not None:
        age_days = (datetime.now() - creation_date).days
        remaining_days = MAX_PASSWORD_AGE_DAYS - age_days
        if remaining_days <= 0:
            feedback.append('Your password has expired. Please change it immediately.')
            score_percent = 0
        elif remaining_days <= 7:
            feedback.append(f'Your password will expire in {remaining_days} days. Please consider changing it soon.')
            score_percent = min(score_percent, 20)
    
    # Construct feedback message
    if score_percent < 20: 
        feedback.append('Your password is very strong.')
    elif score_percent < 40: 
        feedback.append('Your password is stong')
    elif score_percent < 60: 
        feedback.append('Your password is okay, but it can be improved.')
    elif score_percent < 80:
        feedback.append('Your password is weak.')
    else: 
        feedback.append('Your password is very weak.')

    return {'score': max(0, score), 'feedback': '\n'.join(feedback)}

if __name__ == '__main__':
    password = getpass.getpass(prompt='Enter your password: ')
    result = calculate_password_strength(password)
    print(f'Score: {result["score"]}')
    print(result['feedback'])
