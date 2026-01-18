class KnowledgeBase:
    def __init__(self):
        self.tokens = [] # List of captured JWTs/Keys
        self.credentials = [] # List of {"user": "", "pass": ""}
        self.users = set() # Collected usernames/emails
        self.discovered_paths = set()
        
    def add_token(self, token):
        if token and token not in self.tokens:
            self.tokens.append(token)
            return True
        return False
        
    def add_user(self, user):
        if user and user not in self.users:
            self.users.add(user)
            return True
        return False
        
    def add_credential(self, username, password):
        cred = {"user": username, "pass": password}
        if cred not in self.credentials:
            self.credentials.append(cred)
            return True
        return False
        
    def get_best_token(self):
        """ Returns the most likely valid token (e.g. latest one) """
        return self.tokens[-1] if self.tokens else None

# Singleton
kb = KnowledgeBase()
