from zxcvbn import zxcvbn

def check_password_complexity(password):
    result = zxcvbn(password)

    if result["score"] < 3:
        feedback = result["feedback"]
        return False, feedback

    return True, None