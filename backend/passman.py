from flask import Flask, request, jsonify, session
from db.db import create_connection, close_connection, insert_password, encrypt_decrypt_password

app = Flask("PassMan API V0.1.0")

# ROUTES GESTION PASSWORDS

@app.route('/new_passwords', methods=['POST'])
def store_password(user, password_type, name, password):
    if 'google_token' not in session:
        return jsonify({"status": "error", "message": "Unauthenticated, please login first"}), 401
    db_connection = create_connection()

    if db_connection:
        insert_password(db_connection, user, password_type, name, password)
        close_connection(db_connection)
    

@app.route('/get_passwords', methods=['GET'])
def get_passwords():
    if 'google_token' not in session:
        return jsonify({"status": "error", "message": "Unauthenticated, please login first"}), 401
    user = request.args.get('user')

    db_connection = create_connection()

    if db_connection:
        try:
            cursor = db_connection.cursor()

            sql = "SELECT type, name FROM passwords WHERE user = %s"
            cursor.execute(sql, (user,))

            results = cursor.fetchall()

            password_list = [{'type': result[0], 'name': result[1]} for result in results]

            return jsonify({'passwords': password_list})

        except Exception as e:
            return jsonify({'error': f"Erreur lors de la rÃ©cupÃ©ration des mots de passe : {str(e)}"})

        finally:
            close_connection(db_connection)
    else:
        return jsonify({'error': "Impossible de se connecter Ã  la base de donnÃ©es"})


@app.route('/delete_password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    if 'google_token' not in session:
        return jsonify({"status": "error", "message": "Unauthenticated, please login first"}), 401
    db_connection = create_connection()

    if db_connection:
        try:
            cursor = db_connection.cursor()

            sql = "DELETE FROM passwords WHERE id = %s"
            cursor.execute(sql, (password_id,))

            db_connection.commit()

            return jsonify({'message': f"Mot de passe avec l'ID {password_id} supprimÃ© avec succÃ¨s"})

        except Exception as e:
            return jsonify({'error': f"Erreur lors de la suppression du mot de passe : {str(e)}"})

        finally:
            close_connection(db_connection)

    else:
        return jsonify({'error': "Impossible de se connecter Ã  la base de donnÃ©es"})


@app.route('/delete_passwords', methods=['DELETE'])
def delete_passwords():
    if 'google_token' not in session:
        return jsonify({"status": "error", "message": "Unauthenticated, please login first"}), 401
    user = request.args.get('user')

    db_connection = create_connection()

    if db_connection:
        try:
            cursor = db_connection.cursor()

            sql = "DELETE FROM passwords WHERE username = %s"
            cursor.execute(sql, (user,))

            db_connection.commit()

            return jsonify({'message': f"Mots de passe pour {user} supprimÃ©s avec succÃ¨s."})

        except Exception as e:
            return jsonify({'error': f"Erreur lors de la suppression des mots de passe : {str(e)}"})

        finally:
            close_connection(db_connection)

    else:
        return jsonify({'error': "Impossible de se connecter Ã  la base de donnÃ©es"})


@app.route('/update_password', methods=['PUT'])
def update_password():
    if 'google_token' not in session:
        return jsonify({"status": "error", "message": "Unauthenticated, please login first"}), 401
    data = request.get_json()

    user = data.get('user')
    new_password = data.get('new_password')

    db_connection = create_connection()

    if db_connection:
        key = os.getenv('CRYPTO_SECRET_KEY')
        try:
            cursor = db_connection.cursor()

            encrypted_password = encrypt_decrypt_password('encrypt', new_password, key)

            sql = "UPDATE passwords SET password = %s WHERE username = %s"
            cursor.execute(sql, (encrypted_password, user))

            db_connection.commit()

            return jsonify({'message': f"Mot de passe pour {user} mis à jour avec succès."})

        except Exception as e:
            return jsonify({'error': f"Erreur lors de la mise à jour du mot de passe : {str(e)}"})

        finally:
            close_connection(db_connection)

    else:
        return jsonify({'error': "Impossible de se connecter à la base de données"})