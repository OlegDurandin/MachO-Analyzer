from enum import Enum

class SignType(Enum):
    ADHOC = "ad-hoc"
    DEVELOPER_ID = "developer-id"
    APPLE_DEVELOPMENT = "apple-development"

    @classmethod
    def from_string(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return None

class SignInfo:
    def __init__(self):
        self.status = None
        self.sign_type = None
        self.details = {}
        self.developer_info = {}
        self.analyzed_entitlements = {} 