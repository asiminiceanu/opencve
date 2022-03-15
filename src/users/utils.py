import uuid


def is_valid_uuid(val):
    """Check if a given value is a valid UUID"""
    try:
        uuid.UUID(str(val))
    except ValueError:
        return False
    return True
