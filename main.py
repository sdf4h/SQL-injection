from flask import Flask, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)
engine = create_engine('mysql+pymysql://username:password@localhost/dbname')

# Middleware для анализа и предотвращения SQL-инъекций
@app.before_request
def detect_sql_injection():
    # Простой пример проверки на используемые ключевые слова в запросах
    malicious_patterns = ["' OR '1'='1", "UNION SELECT"]
    
    query_string = request.query_string.decode('utf-8')
    if any(pattern in query_string for pattern in malicious_patterns):
        app.logger.warning(f"Detectado patrón sospechoso en la solicitud: {query_string}")
        return jsonify({"error": "Detectada solicitud sospechosa"}), 403

@app.route('/data', methods=['GET'])
def get_data():
    try:
        # Пример безопасного запроса - использовать параметризованные запросы
        with engine.connect() as connection:
            result = connection.execute("SELECT * FROM table_name WHERE id = %s", (request.args.get('id')))
            data = result.fetchall()
            return jsonify(data)
    except SQLAlchemyError as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": "Database error"}), 500

# Включите безопасную авторизацию
# Реализация безопасной авторизации и передачи данных остается за пользователем

if __name__ == "__main__":
    app.run(ssl_context='adhoc')
