import secrets

secret_key = secrets.token_hex(16)
print(secret_key)

class Config:
    SECRET_KEY = 'd80dbd00abe7aa692e13cedf5a379f87'
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_DB = 'user_management'