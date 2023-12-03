import mysql.connector
from mysql.connector import Error
import os



def encrypt_decrypt_password(action, password, key):
    cipher_suite = Fernet(key)
    if action == 'encrypt':
        encrypted_password = cipher_suite.encrypt(password.encode())
        return encrypted_password
    elif action == 'decrypt':
        decrypted_password = cipher_suite.decrypt(password).decode()
        return decrypted_password
    


def create_connection():
    """Crée et renvoie une connexion à la base de données MySQL."""
    try:
        connection = mysql.connector.connect(
            host='localhost',  # Mettez votre adresse IP ou nom d'hôte MySQL
            database='orm',
            user='root',
            password=''
        )
        if connection.is_connected():
            print(f"Connecté à la base de données MySQL - Version {connection.get_server_info()}")
            return connection

    except Error as e:
        print(f"Erreur de connexion à la base de données MySQL: {e}")
        return None

def close_connection(connection):
    """Ferme la connexion à la base de données."""
    if connection.is_connected():
        connection.close()
        print("La connexion à la base de données MySQL a été fermée.")

def insert_password(connection, user,  password_type, name, password):
    try:
        cursor = connection.cursor()

        key = os.getenv('CRYPTO_SECRET_KEY')

        encrypted_password = encrypt_decrypt_password('encrypt', password, key)

        sql = "INSERT INTO passwords (user, type, name, password,) VALUES (%s, %s, %s, %s, %s)"
        values = (user, password_type, name, encrypted_password)
        cursor.execute(sql, values)

        connection.commit()
        print("Mot de passe inséré avec succès.")

    except Error as e:
        print(f"Erreur lors de l'insertion du mot de passe : {e}")



# Test de la connexion
if __name__ == "__main__":
    db_connection = create_connection()
    if db_connection:
        close_connection(db_connection)
