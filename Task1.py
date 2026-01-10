import re


COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "admin", "letmein",
    "welcome","safepassword", "abc123", "password123"
}

def check_dictionary(password):
    return password.lower() not in COMMON_PASSWORDS

def check_length(password):
    return len(password) >= 12

def check_complexity(password):
    checks = {
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        "symbol": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    }
    return checks

def check_patterns(password):
    issues = []

    if re.search(r"(.)\1\1", password):
        issues.append("Repeated characters detected")

    if re.search(r"abc|123|qwerty", password.lower()):
        issues.append("Sequential pattern detected")

    return issues

def analyze_password(password):
    score = 0
    suggestions = []

    if check_dictionary(password):
        score += 1
    else:
        suggestions.append("Avoid common or dictionary-based passwords")

    if check_length(password):
        score += 1
    else:
        suggestions.append("Use at least 12 characters")

    complexity = check_complexity(password)
    score += sum(complexity.values())

    for key, value in complexity.items():
        if not value:
            suggestions.append(f"Add at least one {key} character")

    pattern_issues = check_patterns(password)
    if pattern_issues:
        suggestions.extend(pattern_issues)
    else:
        score += 1

    strength_levels = {
        (0, 3): "Very Weak",
        (4, 5): "Weak",
        (6, 7): "Moderate",
        (8, 9): "Strong"
    }

    strength = "Very Weak"
    for range_, label in strength_levels.items():
        if range_[0] <= score <= range_[1]:
            strength = label

    return {
        "Score": score,
        "Strength": strength,
        "Suggestions": suggestions or ["Password looks strong"]
    }


if __name__ == "__main__":
    pwd = input("Enter password to analyze: ")
    result = analyze_password(pwd)

    print("\nPassword Analysis Result")
    print("-" * 30)
    print("Strength:", result["Strength"])
    print("Score:", result["Score"])
    print("Suggestions:")
    for tip in result["Suggestions"]:
        print("•", tip)
